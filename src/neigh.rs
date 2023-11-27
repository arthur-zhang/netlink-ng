use std::fmt::Display;
use std::net::IpAddr;

use netlink_packet_core::{NLM_F_CREATE, NLM_F_REPLACE};
use netlink_packet_route::{NeighbourMessage, RtnlMessage};

#[derive(Debug, Default)]
pub struct Neigh {
    pub link_index: u32,
    pub family: u32,
    pub state: u32,
    pub type_: u32,
    pub flags: u32,
    pub flags_ext: u32,
    pub ip: Option<IpAddr>,
    pub hardware_addr: Vec<u8>,
    pub llip_addr: Option<IpAddr>,
    pub vlan: u32,
    pub vni: u32,
    pub master_index: u32,
}

impl Display for Neigh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {:?}", self.ip, self.hardware_addr)
    }
}

pub fn neigh_set(neigh: &Neigh) -> anyhow::Result<()> {
    neigh_add(neigh, NLM_F_CREATE | NLM_F_REPLACE)
}

pub fn neigh_add(neigh: &Neigh, flags: u16) -> anyhow::Result<()> {

    let req = NeighbourMessage::default();
    // neigh.

    todo!()


}
// fn neighHandle(neigh: Neigh, req:)