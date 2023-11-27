use std::fs::File;
use std::net::IpAddr;

use netlink_packet_route::{AF_INET, AF_INET6, AF_UNSPEC};

use crate::Namespace;

#[derive(Debug, Default)]
pub struct Dummy {}

#[derive(Debug, Default)]
pub struct Veth {
    pub peer_name: String,
    pub peer_hardware_addr: String,
    pub peer_namespace: Namespace,
}

#[derive(Debug, Default)]
pub struct Bridge {
    pub multicast_snooping: Option<bool>,
    pub ageing_time: Option<u32>,
    pub hello_time: Option<u32>,
    pub vlan_filtering: Option<bool>,
    pub vlan_filtering_pvid: Option<u16>,
}

pub type TuntapMode = u16;
pub type TuntapFlag = u16;

#[derive(Debug, Default)]
pub struct Tuntap {
    pub mode: TuntapMode,
    pub flags: TuntapFlag,
    pub non_persist: bool,
    pub queues: i32,
    pub fds: Vec<File>,
    pub owner: u32,
    pub group: u32,
}

#[derive(Debug, Default)]
pub struct Vxlan {
    pub vxlan_id: u32,
    pub vtep_dev_index: u32,
    pub src_addr: Option<IpAddr>,
    pub group: Option<IpAddr>,
    pub ttl: i32,
    pub tos: i32,
    pub learning: bool,
    pub proxy: bool,
    pub rsc: bool,
    pub l2miss: bool,
    pub l3miss: bool,
    pub udp_csum: bool,
    pub udp6_zero_csum_tx: bool,
    pub udp6_zero_csum_rx: bool,
    pub no_age: bool,
    pub gbp: bool,
    pub flow_based: bool,
    pub age: u32,
    pub limit: u32,
    pub port: u16,
    pub port_low: u16,
    pub port_high: u16,
}


#[derive(Debug, Default)]
pub struct Device {}

pub type Family = u8;

pub const FAMILY_ALL: u8 = AF_UNSPEC as u8;
pub const FAMILY_V4: u8 = AF_INET as u8;
pub const FAMILY_V6: u8 = AF_INET6 as u8;
