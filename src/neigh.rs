use std::fmt::Display;
use std::net::IpAddr;

use libc::{AF_INET, AF_INET6};
use macaddr::MacAddr6;
use netlink_packet_core::{NLM_F_CREATE, NLM_F_REPLACE};
use netlink_packet_route::{IFA_F_PERMANENT, NDA_UNSPEC, NeighbourMessage, RtnlMessage};
use netlink_packet_route::neighbour::Nla;

use crate::handle::NetlinkHandle;

#[derive(Debug)]
pub struct Neigh {
    pub link_index: u32,
    pub family: u8,
    pub state: u16,
    pub type_: u32,
    pub flags: u32,
    // pub flags_ext: u32,
    pub ip: IpAddr,
    pub hardware_addr: MacAddr6,
    // pub llip_addr: Option<IpAddr>,
    pub vlan: u16,
    pub vni: u32,
    pub master_index: u32,
}

impl Default for Neigh {
    fn default() -> Self {
        Self {
            link_index: 0,
            family: 0,
            state: 0,
            type_: 0,
            flags: 0,
            ip: IpAddr::V4("0.0.0.0".parse().unwrap()),
            hardware_addr: MacAddr6::default(),
            vlan: 0,
            vni: 0,
            master_index: 0,
        }
    }
}

impl Display for Neigh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {:?}", self.ip, self.hardware_addr)
    }
}

pub fn neigh_set(neigh: &Neigh) -> anyhow::Result<()> {
    neigh_add(neigh, NLM_F_CREATE | NLM_F_REPLACE)
}

fn new_neigh(neigh: &Neigh, dst: IpAddr) -> NeighbourMessage {
    let mut req = NeighbourMessage::default();
    req.header.family = if dst.is_ipv4() {
        AF_INET as u8
    } else {
        AF_INET6 as u8
    };
    req.header.ifindex = neigh.link_index;
    req.header.state = IFA_F_PERMANENT as u16;
    req.header.ntype = NDA_UNSPEC as u8;
    req.nlas.push(Nla::Destination(match dst {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }));

    req
}

pub fn neigh_add(neigh: &Neigh, flags: u16) -> anyhow::Result<()> {
    let mut req = NeighbourMessage::default();

    req.header.ifindex = neigh.link_index;
    req.header.state = neigh.state;
    req.header.ntype = neigh.type_ as u8;
    req.header.flags = neigh.flags as u8;

    if neigh.family > 0 {
        req.header.family = neigh.family;
    } else {
        req.header.family = if neigh.ip.is_ipv4() {
            AF_INET as u8
        } else {
            AF_INET6 as u8
        };
    }

    req.nlas.push(Nla::Destination(match neigh.ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }));

    if !neigh.hardware_addr.is_nil() {
        req.nlas.push(Nla::LinkLocalAddress(neigh.hardware_addr.into_array().to_vec()));
    }

    if neigh.vlan > 0 {
        req.nlas.push(Nla::Vlan(neigh.vlan));
    }
    if neigh.vni > 0 {
        req.nlas.push(Nla::Vni(neigh.vni));
    }
    if neigh.master_index > 0 {
        req.nlas.push(Nla::Master(u32::to_ne_bytes(neigh.master_index).to_vec()));
    }
    for nla in &req.nlas {
        println!("nla: {:?}", nla)
    }

    let _ = NetlinkHandle::new().execute(RtnlMessage::NewNeighbour(req), flags)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use netlink_packet_route::NUD_PERMANENT;

    use super::*;

    #[test]
    fn test_neigh_set() {
        let neigh = Neigh {
            link_index: 5,
            state: NUD_PERMANENT,
            ip: "10.0.0.4".parse().unwrap(),
            hardware_addr: "3a:91:c1:3f:ee:54".parse().unwrap(),
            ..Default::default()
        };
        let _ = neigh_set(&neigh);
    }
}