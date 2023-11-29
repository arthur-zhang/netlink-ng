#[allow(dead_code)]
use std::net::{IpAddr, Ipv4Addr};

use anyhow::{anyhow, bail};
use ipnetwork::IpNetwork;
use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST};
use netlink_packet_route::{RouteFlags, RouteMessage, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN, RT_TABLE_UNSPEC, RTM_F_CLONED, RTN_UNICAST, RTN_UNSPEC, RTNH_F_ONLINK, RtnlMessage, RTPROT_BOOT, RTPROT_UNSPEC};
use netlink_packet_route::route::Nla;

pub use constants::*;

use crate::{LinkIndex, unwrap_enum, utils};
use crate::handle::NetlinkHandle;
use crate::nl_type::Family;
use crate::types::{Route, RouteProtocol};
use crate::utils::bytes_to_ip;

#[allow(dead_code)]
mod constants {
    pub const RT_FILTER_PROTOCOL: u64 = 1 << 1;
    pub const RT_FILTER_SCOPE: u64 = 1 << 2;
    pub const RT_FILTER_TYPE: u64 = 1 << 3;
    pub const RT_FILTER_TOS: u64 = 1 << 4;
    pub const RT_FILTER_IIF: u64 = 1 << 5;
    pub const RT_FILTER_OIF: u64 = 1 << 6;
    pub const RT_FILTER_DST: u64 = 1 << 7;
    pub const RT_FILTER_SRC: u64 = 1 << 8;
    pub const RT_FILTER_GW: u64 = 1 << 9;
    pub const RT_FILTER_TABLE: u64 = 1 << 10;
    pub const RT_FILTER_HOPLIMIT: u64 = 1 << 11;
    pub const RT_FILTER_PRIORITY: u64 = 1 << 12;
    pub const RT_FILTER_MARK: u64 = 1 << 13;
    pub const RT_FILTER_MASK: u64 = 1 << 14;
    pub const RT_FILTER_REALM: u64 = 1 << 15;
}

pub mod types {
    use std::net::{IpAddr, Ipv4Addr};

    use ipnetwork::IpNetwork;

    pub type Scope = u8;

    pub type RouteProtocol = i32;

    #[derive(Debug, Clone, Default)]
    pub struct Route {
        pub link_index: u32,
        pub i_link_index: u32,
        pub scope: Scope,
        pub dst: Option<IpNetwork>,
        pub src: Option<IpAddr>,
        pub gw: Option<IpAddr>,
        pub multi_path: Option<Vec<NextHopInfo>>,
        pub protocol: RouteProtocol,
        pub priority: u32,
        pub family: i32,
        pub table: Option<u32>,
        pub r#type: i32,
        pub tos: i32,
        pub flags: u32,
        pub mpls_dst: Option<i32>,
        pub new_dst: Destination,
        pub encap: Encap,
        pub via: Destination,
        pub realm: i32,
        pub mtu: i32,
        pub window: i32,
        pub rtt: i32,
        pub rtt_var: i32,
        pub ssthresh: i32,
        pub cwnd: i32,
        pub adv_mss: i32,
        pub reordering: i32,
        pub hop_limit: i32,
        pub init_cwnd: i32,
        pub features: i32,
        pub rto_min: i32,
        pub init_rwnd: i32,
        pub quick_ack: i32,
        pub cong_ctl: String,
        pub fast_open_no_cookie: i32,
    }

    #[derive(Debug, Clone)]
    pub struct NextHopInfo {
        pub link_index: i32,
        pub hops: i32,
        pub gw: IpAddr,
        pub flags: i32,
        pub new_dst: Destination,
        pub encap: Encap,
        pub via: Destination,
    }

    impl Default for NextHopInfo {
        fn default() -> Self {
            Self {
                link_index: 0,
                hops: 0,
                gw: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                flags: 0,
                new_dst: Default::default(),
                encap: Default::default(),
                via: Default::default(),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum Destination {
        MPLSDestination,
        Via,
    }

    impl Default for Destination {
        fn default() -> Self {
            Self::Via
        }
    }

    #[derive(Debug, Clone)]
    pub enum Encap {
        BpfEncap,
        MPLSEncap,
        SEG6Encap,
        SEG6LocalEncap,
    }

    impl Default for Encap {
        fn default() -> Self {
            Self::BpfEncap
        }
    }
}

#[allow(dead_code)]
enum ReqType {
    Add,
    Del,
    Get,
    // Change,
}

pub fn route_add_ecmp(route: &Route) -> anyhow::Result<()> {
    let flags = NLM_F_CREATE | NLM_F_ACK;
    route_handle(route, ReqType::Add, flags)
}

pub fn route_add(route: &Route) -> anyhow::Result<()> {
    let flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    route_handle(route, ReqType::Add, flags)
}

pub fn route_replace(route: &Route) -> anyhow::Result<()> {
    let flags = NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    route_handle(route, ReqType::Add, flags)
}

fn new_route_msg() -> RouteMessage {
    let mut msg = RouteMessage::default();
    msg.header.table = RT_TABLE_MAIN;
    msg.header.scope = RT_SCOPE_UNIVERSE;
    msg.header.protocol = RTPROT_BOOT;
    msg.header.kind = RTN_UNICAST;
    msg
}

fn route_handle(route: &Route, req_type: ReqType, flags: u16) -> anyhow::Result<()> {
    if route.dst.is_none() && route.src.is_none() && route.gw.is_none() && route.mpls_dst.is_none()
    {
        bail!("route dst, src, gw can not be all none");
    }
    let mut msg = new_route_msg();
    if let Some(dst_ip_addr) = &route.dst {
        msg.header.destination_prefix_length = dst_ip_addr.prefix();
        let dst_bytes = utils::ip_to_bytes(&dst_ip_addr.ip());
        msg.nlas.push(Nla::Destination(dst_bytes));
    }
    let gw = route.gw.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    msg.nlas.push(Nla::Gateway(utils::ip_to_bytes(&gw)));
    let family = utils::ip_to_family(&gw);

    msg.header.address_family = family;
    msg.header.flags = route.flags;
    if let Some(table) = route.table {
        if table > 0 {
            if table > u8::MAX as u32 {
                msg.header.table = RT_TABLE_UNSPEC;
                msg.nlas.push(Nla::Table(table));
            } else {
                msg.header.table = table as u8;
            }
        }
    }
    msg.header.table = RT_TABLE_MAIN;
    msg.nlas.push(Nla::Oif(route.link_index));

    let msg = match req_type {
        ReqType::Add => RtnlMessage::NewRoute(msg),
        ReqType::Del => {
            todo!()
        }
        ReqType::Get => {
            todo!()
        }
    };

    NetlinkHandle::new().execute(msg, flags)?;
    Ok(())
}

pub fn route_list(link_id: Option<LinkIndex>, family: Family) -> anyhow::Result<Vec<Route>> {
    let mut filter = None;
    if let Some(link_id) = link_id {
        filter = Some(Route { link_index: link_id, ..Default::default() });
    };

    route_list_filtered(family, filter, RT_FILTER_OIF)
}

pub fn route_list_filtered(family: Family, route_filter: Option<Route>, filter_mask: u64) -> anyhow::Result<Vec<Route>> {
    let mut msg = new_route_msg();
    msg.header.address_family = family;
    msg.header.destination_prefix_length = 0;
    msg.header.source_prefix_length = 0;
    msg.header.scope = RT_SCOPE_UNIVERSE;
    msg.header.kind = RTN_UNSPEC;
    msg.header.table = RT_TABLE_UNSPEC;
    msg.header.protocol = RTPROT_UNSPEC;
    let vec = NetlinkHandle::new().execute(RtnlMessage::GetRoute(msg), NLM_F_REQUEST | NLM_F_DUMP)?;
    let mut routes = vec![];
    for m in vec {
        let route = msg_to_route(m)?;
        if route.flags & RTM_F_CLONED != 0 {
            continue;
        }
        if let Some(table) = route.table {
            if table != RT_TABLE_MAIN as u32 {
                if route_filter.is_none() || (route_filter.is_some() && filter_mask & RT_FILTER_TABLE == 0) {
                    // ignore non-main tables
                    continue;
                }
            }
        }
        if let Some(filter) = &route_filter {
            if filter_mask & RT_FILTER_OIF != 0 && route.link_index != filter.link_index {
                continue;
            }
        }
        routes.push(route);
    }
    Ok(routes)
}

fn msg_to_route(msg: RtnlMessage) -> anyhow::Result<Route> {
    let msg: Option<RouteMessage> = unwrap_enum!(msg, RtnlMessage::NewRoute);
    let msg: RouteMessage = msg.ok_or(anyhow!("msg is not new route"))?;
    let mut route = Route {
        protocol: msg.header.protocol as RouteProtocol,
        family: msg.header.address_family as i32,
        table: Some(msg.header.table as u32),
        r#type: msg.header.kind as i32,
        tos: msg.header.tos as i32,
        flags: msg.header.flags,
        ..Default::default()
    };
    let family = route.family as Family;
    for m in msg.nlas {
        match m {
            Nla::Gateway(gw) => {
                let ip = bytes_to_ip(&gw, family)?;
                route.gw = Some(ip);
            }
            Nla::Table(table) => {
                route.table = Some(table);
            }
            Nla::Oif(oif) => {
                route.link_index = oif;
            }
            Nla::Priority(priority) => {
                route.priority = priority;
            }
            Nla::Destination(dst) => {
                let dst_ip = bytes_to_ip(&dst, family)?;
                route.dst = Some(IpNetwork::new(dst_ip, msg.header.destination_prefix_length)?);
            }

            Nla::PrefSource(src) => {
                let src_ip = bytes_to_ip(&src, family)?;
                route.src = Some(src_ip);
            }
            _ => {
                // println!(">>>>>>>>>>>>{:?}", m);
            }
        }
    }
    Ok(route)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ipnetwork::{IpNetwork, Ipv4Network};
    use log::info;

    use crate::{link_by_name, TryAsLinkIndex};
    use crate::nl_type::FAMILY_V4;

    use super::*;

    #[test]
    fn test_route_add() {
        let link = link_by_name("eth0").unwrap().unwrap();
        // let link = link_by_name("vethhost").unwrap().unwrap();
        let route = Route {
            link_index: link.link_attrs.index,
            dst: Some(IpNetwork::V4(
                Ipv4Network::with_netmask(
                    Ipv4Addr::new(192, 168, 0, 0),
                    Ipv4Addr::new(255, 255, 255, 0),
                )
                    .unwrap(),
            )),
            gw: Some(IpAddr::V4(Ipv4Addr::new(198, 19, 249, 1))),
            ..Default::default()
        };
        let res = route_add_ecmp(&route);
        info!("res: {:?}", res);
    }

    #[test]
    fn test_route_list() -> anyhow::Result<()> {
        let link_id = "flannel0".try_as_index()?.unwrap();
        let routes = route_list(Some(link_id), FAMILY_V4)?;
        // let routes = route_list(None, FAMILY_V4)?;
        for r in routes {
            println!("result::::::::::::{:?}", r);
        }
        Ok(())
    }
}
