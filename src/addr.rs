use std::net::{IpAddr, Ipv4Addr};

use anyhow::anyhow;
use ipnetwork::{IpNetwork, Ipv4Network};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP};
use netlink_packet_route::address::{AddressMessage, Nla};
use netlink_packet_route::RtnlMessage;

use crate::{LinkIndex, utils};
use crate::handle::NetlinkHandle;
use crate::nl_type::{Family, FAMILY_ALL, FAMILY_V4};

#[derive(Debug)]
pub struct Addr {
    pub ipnet: IpNetwork,
    pub label: String,
    pub flags: u32,
    pub scope: i32,
    pub peer: Option<IpNetwork>,
    pub broadcast: Option<IpAddr>,
    pub preferred_lft: i32,
    pub valid_lft: i32,
    pub link_index: u32,
}

impl Eq for Addr {}

impl PartialEq for Addr {
    fn eq(&self, other: &Self) -> bool {
        self.ipnet == other.ipnet
    }
}

impl Default for Addr {
    fn default() -> Self {
        Self {
            ipnet: IpNetwork::V4(Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()),
            label: "".to_string(),
            flags: 0,
            scope: 0,
            peer: None,
            broadcast: None,
            preferred_lft: 0,
            valid_lft: 0,
            link_index: 0,
        }
    }
}

pub enum ReqType {
    Add,
    Del,
    Get,
    Change,
}

pub fn addr_add(link_idx: LinkIndex, addr: &Addr) -> anyhow::Result<()> {
    addr_handle(link_idx, addr, ReqType::Add)
}

fn addr_handle(link_idx: LinkIndex, addr: &Addr, req_type: ReqType) -> anyhow::Result<()> {
    let mut msg = AddressMessage::default();
    msg.header.index = link_idx;
    msg.header.scope = addr.scope as u8;
    let mut _mask = addr.ipnet.mask();
    if let Some(addr_peer) = &addr.peer {
        _mask = addr_peer.mask();
    }
    let prefix = addr.ipnet.prefix();
    msg.header.prefix_len = prefix;
    msg.header.family = utils::ip_to_family(&addr.ipnet.ip());
    let local_addr_vec = utils::ip_to_bytes(&addr.ipnet.ip());

    let peer_addr_vec = if let Some(peer) = addr.peer {
        utils::ip_to_bytes(&peer.ip())
    } else {
        local_addr_vec.clone()
    };

    msg.nlas.push(Nla::Local(local_addr_vec.clone()));
    msg.nlas.push(Nla::Address(peer_addr_vec.clone()));

    if addr.ipnet.is_ipv4() {
        let broadcast_addr = if addr.broadcast.is_none() && prefix < 31 {
            Some(addr.ipnet.broadcast())
        } else {
            addr.broadcast.clone()
        };
        if let Some(broadcast_addr) = broadcast_addr {
            msg.nlas
                .push(Nla::Broadcast(utils::ip_to_bytes(&broadcast_addr)));
        }
    }
    if !addr.label.is_empty() {
        msg.nlas.push(Nla::Label(addr.label.clone()));
    }

    let msg = match req_type {
        ReqType::Add => RtnlMessage::NewAddress(msg),
        ReqType::Del => RtnlMessage::DelAddress(msg),
        ReqType::Get => {
            todo!()
        }
        ReqType::Change => {
            todo!()
        }
    };
    NetlinkHandle::new().execute(msg, NLM_F_ACK)?;
    Ok(())
}

pub fn addr_del(link_index: LinkIndex, addr: &Addr) -> anyhow::Result<()> {
    addr_handle(link_index, addr, ReqType::Del)?;
    Ok(())
}

pub fn addr_list(link_index: LinkIndex, family: Family) -> anyhow::Result<Vec<Addr>> {
    let mut msg = AddressMessage::default();
    msg.header.family = family;

    let result_vec = NetlinkHandle::new().execute(RtnlMessage::GetAddress(msg), NLM_F_DUMP | NLM_F_ACK)?;
    let mut result = Vec::new();
    for msg in &result_vec {
        if let RtnlMessage::NewAddress(addr) = msg {
            if addr.header.index != link_index {
                continue;
            }

            if family != FAMILY_ALL && addr.header.family != family {
                continue;
            }
            let addr = Addr::try_from(addr)?;
            result.push(addr);
        }
    }

    Ok(result)
}

impl TryFrom<&AddressMessage> for Addr {
    type Error = anyhow::Error;

    fn try_from(msg: &AddressMessage) -> Result<Self, Self::Error> {
        let mut addr = Addr::default();
        addr.link_index = msg.header.index;
        let mut dst = None;
        let mut local = None;

        let family = u8::from(msg.header.family);
        for attr in &msg.nlas {
            match attr {
                Nla::Unspec(_) => {}
                Nla::Address(addr) => {
                    let ip = utils::bytes_to_ip(addr, family)?;
                    let prefix = msg.header.prefix_len;
                    dst = Some(IpNetwork::new(ip, prefix)?);
                }
                Nla::Local(bytes) => {
                    let n = bytes.len() * 8;
                    let ip = utils::bytes_to_ip(bytes, family)?;
                    let ip = IpNetwork::new(ip, n as u8).map_err(|_| anyhow!("invalid ip"))?;
                    local = Some(ip);
                }
                Nla::Label(label) => {
                    addr.label = label.clone();
                }
                Nla::Broadcast(bytes) => {
                    addr.broadcast = Some(utils::bytes_to_ip(bytes, family)?);
                }
                Nla::Anycast(_) => {}
                Nla::CacheInfo(_) => {}
                Nla::Multicast(_) => {}
                Nla::Flags(flags) => {
                    addr.flags = *flags;
                }
                Nla::Other(_) => {}
                _ => {}
            }
        }
        if let Some(local) = local {
            if family == FAMILY_V4 && dst.is_some() && dst.unwrap().ip() == local.ip() {
                addr.ipnet = dst.unwrap();
            } else {
                addr.ipnet = local;
                addr.peer = dst;
            }
        } else {
            if let Some(dst) = dst {
                addr.ipnet = dst;
            }
        }
        addr.scope = u8::from(msg.header.scope) as i32;

        Ok(addr)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ipnetwork::Ipv4Network;
    use log::info;

    use crate::{link_by_name, TryAsLinkIndex};

    use super::*;

    #[test]
    fn test_addr_add() {
        let link = link_by_name("vethhost").unwrap().unwrap();
        let result = addr_add(
            link.attrs().index,
            &Addr {
                ipnet: IpNetwork::V4(
                    Ipv4Network::new(Ipv4Addr::new(198, 19, 249, 211), 16).unwrap(),
                ),
                ..Default::default()
            },
        );
    }

    #[test]
    fn test_addr_del() {
        let link = "vxlan0".try_as_index().unwrap().unwrap();
        let res = addr_del(
            link,
            &Addr {
                ipnet: IpNetwork::V4(
                    Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 4), 24).unwrap(),
                ),
                ..Default::default()
            },
        );
        println!("res: {:?}", res);
    }

    #[test]
    fn test_addr_list() {
        // let link = link_by_name("br666").unwrap().unwrap();
        let link = link_by_name("vxlan0").unwrap().unwrap();
        let result = addr_list(link.as_index(), FAMILY_ALL);
        println!("result: {:?}", result);
        match result {
            Ok(result) => {
                for addr in result {
                    info!("result: {:?}", addr);
                }
            }
            Err(err) => {
                info!("err: {:?}", err);
            }
        }
    }
}
