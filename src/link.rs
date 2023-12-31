use std::os::fd::RawFd;

use anyhow::bail;
use log::{debug, info};
use macaddr::MacAddr6;
use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL};
use netlink_packet_route::{AF_UNSPEC, IFF_ALLMULTI, IFF_BROADCAST, IFF_LOOPBACK, IFF_MULTICAST, IFF_POINTOPOINT, IFF_PROMISC, IFF_UP, LinkMessage, RTEXT_FILTER_VF, RtnlMessage};
use netlink_packet_route::link::nlas::{Info, InfoBridge, InfoData, InfoKind, InfoVxlan, Nla, State, Stats64Buffer, VethInfo};
use netlink_packet_route::nlas::link::Stats64;
use netlink_packet_utils::Parseable;

use crate::{nl_linux, rtnl_msg_ext, utils};
use crate::handle::NetlinkHandle;
use crate::nl_type::{Bridge, Dummy, Tuntap, Veth, Vxlan};

pub type Stats = Stats64;
pub type OperState = State;

// pub mod link;
#[derive(Debug)]
pub struct LinkAttrs {
    pub index: u32,
    pub mtu: u32,
    // Transmit Queue Length
    pub tx_q_len: u32,
    pub name: String,
    pub hardware_addr: Option<MacAddr6>,
    pub flags: u32,
    pub raw_flags: u32,
    pub parent_index: u32,
    pub master_index: u32,
    pub namespace: Option<Namespace>,
    pub alias: String,
    pub statistics: Option<Stats>,
    pub promisc: i32,
    pub allmulti: i32,
    pub multi: i32,
    // xdp: Option<LinkXdp>,
    pub encap_type: String,
    // protinfo: Option<Protinfo>,
    pub oper_state: OperState,
    pub phys_switch_id: u32,
    pub net_ns_id: i32,
    pub num_tx_queues: u32,
    pub num_rx_queues: u32,
    pub gso_max_size: u32,
    pub gso_max_segs: u32,
    // vfs: Vec<u8>,
    pub group: u32,
    // slave: LinkSlave,
}

impl LinkAttrs {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Default for LinkAttrs {
    fn default() -> Self {
        Self {
            index: 0,
            mtu: 0,
            tx_q_len: 0,
            name: "".to_string(),
            hardware_addr: None,
            flags: 0,
            raw_flags: 0,
            parent_index: 0,
            master_index: 0,
            namespace: None,
            alias: "".to_string(),
            statistics: None,
            promisc: 0,
            allmulti: 0,
            multi: 0,
            encap_type: "".to_string(),
            oper_state: State::Unknown,
            phys_switch_id: 0,
            net_ns_id: 0,
            num_tx_queues: 0,
            num_rx_queues: 0,
            gso_max_size: 0,
            gso_max_segs: 0,
            group: 0,
        }
    }
}

#[derive(Debug)]
pub enum Namespace {
    NsPid(u32),
    NsFd(u32),
}

impl Default for Namespace {
    fn default() -> Self {
        Namespace::NsPid(0)
    }
}

#[derive(Debug)]
pub struct Link {
    pub link_attrs: LinkAttrs,
    pub link_kind: LinkKind,
}


impl Link {
    pub fn new(link_attrs: LinkAttrs, link_kind: LinkKind) -> Self {
        Self {
            link_attrs,
            link_kind,
        }
    }
    pub fn as_index(&self) -> u32 {
        self.link_attrs.index
    }
    pub fn kind(&self) -> &'static str {
        self.link_kind.kind()
    }
}

#[derive(Debug)]
pub enum LinkKind {
    Veth(Veth),
    Bridge(Bridge),
    Tuntap(Tuntap),
    Vxlan(Vxlan),
    Device,
    Dummy(Dummy),
}

impl LinkKind {
    pub fn kind(&self) -> &'static str {
        match self {
            LinkKind::Veth(_) => "veth",
            LinkKind::Bridge(_) => "bridge",
            LinkKind::Tuntap(_) => "tuntap",
            LinkKind::Vxlan(_) => "vxlan",
            LinkKind::Dummy(_) => "dummy",
            LinkKind::Device => "device",
        }
    }
}


impl Link {
    pub fn attrs(&self) -> &LinkAttrs {
        &self.link_attrs
    }
    pub fn set_attrs(&mut self, attrs: LinkAttrs) {
        self.link_attrs = attrs;
    }
}

pub fn link_by_index(index: u32) -> anyhow::Result<Option<Link>> {
    let mut msg = LinkMessage::default();
    msg.header.index = index;
    let resp = NetlinkHandle::new().execute(RtnlMessage::GetLink(msg), NLM_F_ACK)?;
    if resp.len() == 0 {
        return Ok(None);
    }
    if resp.len() > 1 {
        bail!("multiple links found for id: {}", index);
    }

    let resp_msg = resp.first().unwrap();
    let link = link_deserialize(resp_msg)?;
    Ok(Some(link))
}

pub fn link_by_name(name: &str) -> anyhow::Result<Option<Link>> {
    let mut msg = LinkMessage::default();
    msg.header.interface_family = AF_UNSPEC as u8;
    msg.nlas.push(Nla::ExtMask(RTEXT_FILTER_VF));
    msg.nlas.push(Nla::IfName(name.to_string()));

    let resp = NetlinkHandle::new().execute(RtnlMessage::GetLink(msg), NLM_F_ACK)?;
    if resp.len() == 0 {
        return Ok(None);
    }
    if resp.len() > 1 {
        bail!("multiple links found for name: {}", name);
    }

    let resp_msg = resp.first().unwrap();
    let link = link_deserialize(resp_msg)?;
    Ok(Some(link))
}

pub fn link_add(link: &Link) -> anyhow::Result<()> {
    link_modify(link, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK)
}

pub fn link_list() -> anyhow::Result<Vec<Link>> {
    let mut msg = LinkMessage::default();
    msg.header.interface_family = AF_UNSPEC as u8;
    msg.nlas.push(Nla::ExtMask(RTEXT_FILTER_VF));

    let res = NetlinkHandle::new()
        .execute(RtnlMessage::GetLink(msg), NLM_F_ACK | NLM_F_DUMP)?
        .iter()
        .map(|it| link_deserialize(it))
        .collect::<Vec<_>>();
    let res: Result<Vec<_>, _> = res.into_iter().collect();
    let links: Vec<Link> = res?;
    Ok(links)
}

pub type LinkIndex = u32;

pub trait AsLinkIndex {
    fn as_index(&self) -> LinkIndex;
}

pub trait TryAsLinkIndex {
    fn try_as_index(&self) -> anyhow::Result<Option<LinkIndex>>;
}

impl AsLinkIndex for Link {
    fn as_index(&self) -> LinkIndex {
        self.link_attrs.index
    }
}

impl TryAsLinkIndex for Link {
    fn try_as_index(&self) -> anyhow::Result<Option<LinkIndex>> {
        if self.attrs().index == 0 {
            return self.attrs().name.as_str().try_as_index();
        }
        Ok(Some(self.link_attrs.index))
    }
}

impl TryAsLinkIndex for &str {
    fn try_as_index(&self) -> anyhow::Result<Option<LinkIndex>> {
        let link = link_by_name(self)?;
        match link {
            None => {
                Ok(None)
            }
            Some(link) => {
                Ok(Some(link.link_attrs.index))
            }
        }
    }
}

impl AsLinkIndex for u32 {
    fn as_index(&self) -> LinkIndex {
        *self
    }
}

pub fn link_del(link_index: LinkIndex) -> anyhow::Result<()> {
    // let index = match get_link_index(&link) {
    //     Ok(index) => index,
    //     Err(e) => {
    //         if let Some(it) = e.downcast_ref::<std::io::Error>() {
    //             if it.kind() == NotFound {
    //                 return Ok(());
    //             }
    //         }
    //         return Err(e);
    //     }
    // };

    let mut msg = LinkMessage::default();
    msg.header.index = link_index;

    let res = NetlinkHandle::new().execute(RtnlMessage::DelLink(msg), NLM_F_ACK)?;
    for x in res {
        debug!("x: {:?}", x);
    }

    Ok(())
}

pub fn link_set_up(link: LinkIndex) -> anyhow::Result<()> {
    let mut msg = LinkMessage::default();
    msg.header.index = link;
    msg.header.flags |= IFF_UP;
    msg.header.change_mask |= IFF_UP;
    let _ = NetlinkHandle::new().execute(
        RtnlMessage::SetLink(msg),
        NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
    )?;
    Ok(())
}

pub fn link_set_down(link: &Link) -> anyhow::Result<()> {
    let mut msg = LinkMessage::default();
    msg.header.index = link.attrs().index;
    msg.header.flags &= !IFF_UP;
    msg.header.change_mask |= IFF_UP;
    let _ = NetlinkHandle::new().execute(RtnlMessage::SetLink(msg), NLM_F_ACK)?;
    Ok(())
}

fn link_modify(link: &Link, flags: u16) -> anyhow::Result<()> {
    let base = link.attrs();

    let mut msg = LinkMessage::default();

    if base.flags & IFF_UP != 0 {
        msg.header.change_mask |= IFF_UP;
        msg.header.flags |= IFF_UP;
    }
    if base.flags & IFF_BROADCAST != 0 {
        msg.header.change_mask |= IFF_BROADCAST;
        msg.header.flags |= IFF_BROADCAST;
    }
    if base.flags & IFF_LOOPBACK != 0 {
        msg.header.change_mask |= IFF_LOOPBACK;
        msg.header.flags |= IFF_LOOPBACK;
    }
    if base.flags & IFF_POINTOPOINT != 0 {
        msg.header.change_mask |= IFF_POINTOPOINT;
        msg.header.flags |= IFF_POINTOPOINT;
    }
    if base.flags & IFF_MULTICAST != 0 {
        msg.header.change_mask |= IFF_MULTICAST;
        msg.header.flags |= IFF_MULTICAST;
    }
    if base.index != 0 {
        msg.header.index = base.index;
    }
    if base.parent_index != 0 {
        // todo
    }

    msg.nlas.push(Nla::IfName(base.name.clone()));
    if base.mtu > 0 {
        msg.nlas.push(Nla::Mtu(base.mtu));
    }
    if base.tx_q_len > 0 {
        msg.nlas.push(Nla::TxQueueLen(base.tx_q_len));
    }
    if let Some(addr) = &base.hardware_addr {
        msg.nlas.push(Nla::Address(addr.into_array().to_vec()));
    }
    if base.num_tx_queues > 0 {
        msg.nlas.push(Nla::NumTxQueues(base.num_tx_queues));
    }
    if base.num_rx_queues > 0 {
        msg.nlas.push(Nla::NumRxQueues(base.num_rx_queues));
    }
    if base.gso_max_segs > 0 {
        msg.nlas.push(Nla::GsoMaxSegs(base.gso_max_segs));
    }
    if base.gso_max_size > 0 {
        msg.nlas.push(Nla::GsoMaxSize(base.gso_max_size));
    }
    // todo GSOIPv4MaxSize,GROIPv4MaxSize
    if base.group > 0 {
        msg.nlas.push(Nla::Group(base.group));
    }

    if let Some(namespace) = &base.namespace {
        match namespace {
            Namespace::NsPid(pid) => {
                msg.nlas.push(Nla::NetNsPid(*pid));
            }
            Namespace::NsFd(fd) => {
                msg.nlas.push(Nla::NetNsFd(*fd as RawFd));
            }
        }
    }
    // todo xdp

    let mut link_info_nlas = vec![Info::Kind(get_link_kind(&link.link_kind))];
    match &link.link_kind {
        LinkKind::Veth(Veth {
                           peer_name,
                           peer_hardware_addr: _peer_hardware_addr,
                           peer_namespace,
                       }) => {
            let mut peer = LinkMessage::default();
            peer.nlas.push(Nla::IfName(peer_name.clone()));
            peer.nlas.push(Nla::TxQueueLen(base.tx_q_len));
            if base.num_tx_queues > 0 {
                peer.nlas.push(Nla::NumTxQueues(base.num_tx_queues));
            }
            if base.num_rx_queues > 0 {
                peer.nlas.push(Nla::NumRxQueues(base.num_rx_queues));
            }
            if base.mtu > 0 {
                peer.nlas.push(Nla::Mtu(base.mtu));
            }
            // todo handle peer mac
            // if let Some(mac) = &link.link_attrs.hardware_addr {
            //     peer.nlas.push(Nla::Address(mac.to_vec()));
            // }
            match peer_namespace {
                Namespace::NsPid(pid) => {
                    peer.nlas.push(Nla::NetNsPid(*pid));
                }
                Namespace::NsFd(fd) => {
                    info!(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>ns fd: {}", *fd);
                    peer.nlas.push(Nla::NetNsFd(*fd as RawFd));
                }
            }

            link_info_nlas.push(Info::Data(InfoData::Veth(VethInfo::Peer(peer))));
            msg.nlas.push(Nla::Info(link_info_nlas));
        }
        LinkKind::Bridge(Bridge {
                             multicast_snooping,
                             ageing_time,
                             hello_time: _hello_time,
                             vlan_filtering,
                             vlan_filtering_pvid,
                         }) => {
            let mut vec = Vec::new();
            if let Some(v) = multicast_snooping {
                vec.push(InfoBridge::MulticastSnooping(*v as u8));
            }
            if let Some(v) = ageing_time {
                vec.push(InfoBridge::AgeingTime(*v));
            }
            if let Some(v) = vlan_filtering {
                vec.push(InfoBridge::VlanFiltering(*v as u8));
            }
            if let Some(v) = vlan_filtering_pvid {
                vec.push(InfoBridge::VlanDefaultPvid(*v));
            }
            if !vec.is_empty() {
                link_info_nlas.push(Info::Data(InfoData::Bridge(vec)));
            }
            msg.nlas.push(Nla::Info(link_info_nlas));
        }
        LinkKind::Device => {
            unimplemented!()
        }
        LinkKind::Tuntap(_) => {}
        LinkKind::Dummy(_) => {}
        LinkKind::Vxlan(vxlan) => {
            add_vxlan_attrs(&mut msg, link_info_nlas, vxlan);
        }
    }
    let _ = NetlinkHandle::new().execute(RtnlMessage::NewLink(msg), flags)?;

    Ok(())
}

fn add_vxlan_attrs(msg: &mut LinkMessage, mut link_info_nlas: Vec<Info>, vxlan: &Vxlan) {
    let mut vec = vec![
        InfoVxlan::Id(vxlan.vxlan_id)
    ];
    if vxlan.vtep_dev_index > 0 {
        vec.push(InfoVxlan::Link(vxlan.vtep_dev_index));
    }

    if let Some(src_addr) = vxlan.src_addr {
        if src_addr.is_ipv4() {
            vec.push(InfoVxlan::Local(utils::ip_to_bytes(&src_addr)));
        } else {
            vec.push(InfoVxlan::Local6(utils::ip_to_bytes(&src_addr)));
        }
    }
    if let Some(group) = vxlan.group {
        if group.is_ipv4() {
            vec.push(InfoVxlan::Group(utils::ip_to_bytes(&group)));
        } else {
            vec.push(InfoVxlan::Group6(utils::ip_to_bytes(&group)));
        }
    }
    if vxlan.ttl > 0 {
        vec.push(InfoVxlan::Ttl(vxlan.ttl as u8));
    }
    if vxlan.tos > 0 {
        vec.push(InfoVxlan::Tos(vxlan.tos as u8));
    }
    if vxlan.learning {
        vec.push(InfoVxlan::Learning(1));
    }
    if vxlan.proxy {
        vec.push(InfoVxlan::Proxy(1));
    }
    if vxlan.rsc {
        vec.push(InfoVxlan::Rsc(1));
    }
    if vxlan.l2miss {
        vec.push(InfoVxlan::L2Miss(1));
    }
    if vxlan.l3miss {
        vec.push(InfoVxlan::L3Miss(1));
    }
    if vxlan.udp6_zero_csum_tx {
        vec.push(InfoVxlan::UDPZeroCsumTX(1));
    }
    if vxlan.udp6_zero_csum_rx {
        vec.push(InfoVxlan::UDPZeroCsumRX(1));
    }
    if vxlan.udp_csum {
        vec.push(InfoVxlan::UDPCsum(1));
    }
    if vxlan.gbp {
        vec.push(InfoVxlan::Gbp(1));
    }

    if vxlan.flow_based {
        // todo
    }
    if vxlan.no_age {
        vec.push(InfoVxlan::Ageing(0));
    } else if vxlan.age > 0 {
        vec.push(InfoVxlan::Ageing(vxlan.age));
    }

    if vxlan.limit > 0 {
        vec.push(InfoVxlan::Limit(vxlan.limit));
    }
    if vxlan.port > 0 {
        vec.push(InfoVxlan::Port(vxlan.port));
    }
    if vxlan.port_low > 0 && vxlan.port_high > 0 {
        vec.push(InfoVxlan::PortRange((vxlan.port_low, vxlan.port_high)));
    }
    link_info_nlas.push(Info::Data(InfoData::Vxlan(vec)));
    msg.nlas.push(Nla::Info(link_info_nlas));
}

// LinkSetMaster sets the master of the link device.
// Equivalent to: `ip link set $link master $master`
pub fn link_set_master(link: &Link, master: &Link) -> anyhow::Result<()> {
    let master_index = master.link_attrs.index;
    link_set_master_by_index(link, master_index)
}

fn link_set_master_by_index(link: &Link, master_index: u32) -> anyhow::Result<()> {
    let mut msg = LinkMessage::default();
    msg.header.index = link.attrs().index;
    msg.nlas.push(Nla::Master(master_index));
    let _ = NetlinkHandle::new().execute(RtnlMessage::SetLink(msg), NLM_F_ACK)?;
    Ok(())
}


fn get_link_kind(link: &LinkKind) -> InfoKind {
    match link {
        LinkKind::Veth { .. } => InfoKind::Veth,
        LinkKind::Bridge { .. } => InfoKind::Bridge,
        LinkKind::Device { .. } => InfoKind::Dummy,
        LinkKind::Tuntap { .. } => InfoKind::IpTun,
        LinkKind::Dummy { .. } => { InfoKind::Dummy }
        LinkKind::Vxlan(_) => { InfoKind::Vxlan }
    }
}


fn link_deserialize(msg: &RtnlMessage) -> anyhow::Result<Link> {
    let index = rtnl_msg_ext::index(&msg);
    let flags = rtnl_msg_ext::flags(&msg);
    let attrs = rtnl_msg_ext::attrs(&msg);
    let link_layer_type = rtnl_msg_ext::link_layer_type(&msg);

    let mut base = LinkAttrs::new();
    base.index = index;
    base.raw_flags = flags;
    base.encap_type = nl_linux::encap_type(link_layer_type);
    base.net_ns_id = -1;
    if flags & IFF_PROMISC != 0 {
        base.promisc = 1;
    }
    if flags & IFF_ALLMULTI != 0 {
        base.allmulti = 1;
    }
    if flags & IFF_MULTICAST != 0 {
        base.multi = 1;
    }

    let mut link_kind: Option<LinkKind> = None;
    for attr in attrs {
        match attr {
            Nla::IfName(name) => {
                base.name = name.clone();
            }
            Nla::Address(addr) => {
                let hardware_addr = if addr.len() == 6 {
                    MacAddr6::new(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
                } else {
                    MacAddr6::default()
                };
                base.hardware_addr = Some(hardware_addr);
            }
            Nla::Mtu(mtu) => {
                base.mtu = *mtu;
            }
            Nla::Link(link) => {
                base.parent_index = *link;
            }
            Nla::Master(master) => {
                base.master_index = *master;
            }

            Nla::TxQueueLen(len) => {
                base.tx_q_len = *len;
            }
            Nla::IfAlias(alias) => {
                base.alias = alias.clone();
            }
            Nla::Stats(_stats) => {}
            Nla::Stats64(stats) => {
                let buffer = Stats64Buffer::new(stats);
                base.statistics = Some(Stats64::parse(&buffer).unwrap());
            }
            Nla::Xdp(xdp_data) => {
                // todo
                debug!("xdp_data: {:?}", xdp_data);
            }
            Nla::OperState(state) => {
                base.oper_state = *state;
            }
            Nla::PhysSwitchId(vec) => {
                if vec.len() == 4 {
                    base.phys_switch_id = u32::from_ne_bytes([vec[0], vec[1], vec[2], vec[3]]);
                }
            }
            Nla::NetnsId(id) => {
                base.net_ns_id = *id;
            }
            Nla::GsoMaxSegs(segs) => {
                base.gso_max_segs = *segs;
            }
            Nla::GsoMaxSize(size) => {
                base.gso_max_size = *size;
            }
            Nla::NumTxQueues(queues) => {
                base.num_tx_queues = *queues;
            }
            Nla::NumRxQueues(queues) => {
                base.num_rx_queues = *queues;
            }
            Nla::Group(group) => {
                base.group = *group;
            }
            Nla::VfInfoList(_data) => {
                // base.vfs = data.to_vec();
            }
            Nla::Info(infos) => {
                for info in infos {
                    // debug!("info: {:?}", info);
                    match info {
                        Info::Kind(kind) => match kind {
                            InfoKind::Bridge => {
                                link_kind = Some(LinkKind::Bridge(Bridge::default()));
                            }
                            InfoKind::Veth => {
                                link_kind = Some(LinkKind::Veth(Veth::default()));
                            }
                            InfoKind::IpTun => {
                                link_kind = Some(LinkKind::Tuntap(Tuntap::default()));
                            }
                            InfoKind::Tun => {
                                link_kind = Some(LinkKind::Tuntap(Tuntap::default()));
                            }
                            InfoKind::Vxlan => {
                                link_kind = Some(LinkKind::Vxlan(Vxlan::default()));
                            }
                            _ => {
                                debug!("info kind: {:?}", kind);
                                unimplemented!("info kind: {:?}", kind)
                            }
                        },
                        Info::Data(data) => {
                            match data {
                                InfoData::Bridge(_br) => {
                                    // info!("bridge data: {:?}", br)
                                }
                                InfoData::Tun(_tun) => {
                                    // info!("tun data: {:?}", tun)
                                }
                                _ => {
                                    // println!("data: {:?}", data);
                                }
                            }
                        }
                        Info::PortData(data) => {
                            info!("port data: {:?}", data)
                        }
                        Info::PortKind(data) => {
                            info!("port kind: {:?}", data)
                        }
                        _ => {
                            unimplemented!("info: {:?}", info)
                        }
                    }
                }
            }
            Nla::NetNsFd(fd) => {
                base.net_ns_id = *fd;
            }
            _ => {
                // println!("attr: {:?}", attr);
            }
        }
    }
    if link_kind.is_none() {
        link_kind = Some(LinkKind::Device {});
    }

    return Ok(Link {
        link_attrs: base,
        link_kind: link_kind.unwrap(),
    });
}

pub fn set_promisc_on(index: LinkIndex) -> anyhow::Result<()> {
    let mut msg = LinkMessage::default();
    msg.header.index = index;
    msg.header.flags |= IFF_PROMISC;
    msg.header.change_mask |= IFF_PROMISC;

    NetlinkHandle::new().execute(RtnlMessage::SetLink(msg), NLM_F_ACK)?;
    Ok(())
}

pub fn link_set_mtu(index: LinkIndex, mtu: u32) -> anyhow::Result<()> {
    let mut msg = LinkMessage::default();
    msg.header.index = index;
    msg.header.flags |= IFF_MULTICAST;
    msg.header.change_mask |= IFF_MULTICAST;
    msg.nlas.push(Nla::Mtu(mtu));
    NetlinkHandle::new().execute(RtnlMessage::SetLink(msg), NLM_F_ACK)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs::File;
    use std::os::fd::AsRawFd;

    use rand::Rng;

    use crate::addr_list;
    use crate::nl_type::{Bridge, FAMILY_V4};

    use super::*;

    #[test]
    fn test_link_add_del_with_index() {
        let result = link_list();

        assert!(result.is_ok());
        let result = result.unwrap();
        for link in result {
            println!("link: {}", link.link_attrs.name);
        }
    }

    #[test]
    fn test_link_by_name() -> anyhow::Result<()> {
        let a = link_by_name("vxlan0")?;

        println!("{:?}", a);
        // let a = link_by_name("eth0")?;
        // info!("{:?}", a.unwrap());
        // let a = link_by_name("eth0")?;
        // info!("{:?}", a.unwrap());
        // let a = link_by_name("eth0")?;
        // info!("{:?}", a.unwrap());
        Ok(())
    }

    #[test]
    fn test_link_by_index() -> anyhow::Result<()> {
        // let link = link_by_index(382)?;
        // println!("link: {:?}", link);
        let link = link_by_name("vxlan0")?;
        println!("link: {:?}", link);
        Ok(())
    }

    #[test]
    fn test_set_link_up() -> anyhow::Result<()> {
        let link = link_by_name("br234")?.unwrap();
        let _ = link_set_up(link.as_index());
        let link = link_by_name("br234")?.unwrap();
        debug!("link after set up {:?}", link);
        // assert_eq!(link.attrs().oper_state, State::Up);
        let _ = link_set_down(&link);
        let link = link_by_name("br234")?;
        debug!("link after set down {:?}", link);
        // assert_eq!(link.attrs().oper_state, State::Down);

        Ok(())
    }

    #[test]
    fn test_add_link_bridge() -> anyhow::Result<()> {
        let name = "br234";
        let link = Link {
            link_attrs: LinkAttrs {
                mtu: 1500,
                name: name.to_string(),
                ..Default::default()
            },
            link_kind: LinkKind::Bridge(Bridge::default()),
        };
        link_add(&link)?;
        Ok(())
    }

    #[test]
    fn test_add_link_veth() -> anyhow::Result<()> {
        let name = "vethhost";
        let ns_file = File::open("/var/run/netns/a2").unwrap();
        let link = Link {
            link_attrs: LinkAttrs {
                mtu: 1500,
                name: name.to_string(),
                ..Default::default()
            },
            link_kind: LinkKind::Veth(Veth {
                peer_name: "vethcontainer".to_string(),
                peer_hardware_addr: "".to_string(),
                peer_namespace: Namespace::NsFd(ns_file.as_raw_fd() as u32),
            }),
        };
        link_add(&link)?;
        Ok(())
    }

    #[test]
    fn test_link_list() -> anyhow::Result<()> {
        let res = link_list()?;
        for it in &res {
            debug!("link: {}:{}", it.attrs().name, it.attrs().index)
        }

        Ok(())
    }

    #[test]
    fn test_add_links() -> anyhow::Result<()> {
        for i in 0..100 {
            let name = format!("br{}", i);
            let link = Link {
                link_attrs: LinkAttrs {
                    mtu: 1500,
                    name: name.to_string(),
                    ..Default::default()
                },
                link_kind: LinkKind::Bridge(Bridge::default()),
            };
            link_add(&link)?;
        }
        Ok(())
    }

    #[test]
    fn test_link_del() -> anyhow::Result<()> {
        let link_idx = 100;
        let res = link_del(link_idx);
        println!("res {:?}", res);
        let err = res.unwrap_err();
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            println!("{}", io_err.kind());
            if io_err.kind() == std::io::ErrorKind::NotFound {
                println!("not found...........")
            }
        } else {
            println!("other...........");
        }

        // let links = link_list()?;
        // for it in &links {
        //     link_del(it)?;
        // }
        // for i in 0..1 {
        //     let name = format!("br{i}");
        //     let link_idx = name.as_str().try_as_index()?;
        //     if let Some(link_idx) = link_idx {
        //         let res = link_del(link_idx)?;
        //     }
        //     debug!("res: {:?}", res);
        // }
        //
        Ok(())
    }

    #[test]
    fn test_multiple_add() -> Result<(), Box<dyn Error>> {
        for i in 0..2 {
            let name = "br234";
            let link = Link {
                link_attrs: LinkAttrs {
                    mtu: 1500,
                    name: name.to_string(),
                    ..Default::default()
                },
                link_kind: LinkKind::Bridge(Bridge::default()),
            };
            let res = link_add(&link);
            debug!("{:?}", res);
        }
        Ok(())
    }

    #[test]
    fn test_set_promisc_on() -> anyhow::Result<()> {
        let link_id = "br234".try_as_index()?.unwrap();
        let res = set_promisc_on(link_id);
        assert!(res.is_ok());
        Ok(())
    }

    #[test]
    fn test_set_master() {
        let br = link_by_name("br666").unwrap().unwrap();
        let veth = link_by_name("veth999fc8a5").unwrap().unwrap();
        let res = link_set_master(&veth, &br);
        info!("res: {:?}", res);
    }

    #[test]
    fn test_set_mtu() -> anyhow::Result<()> {
        let link_id = "flannel0".try_as_index()?.unwrap();
        let res = link_set_mtu(link_id, 1400);
        assert!(res.is_ok());
        Ok(())
    }

    #[test]
    fn test_new_vxlan() {
        let eth0_link = link_by_name("eth0").unwrap().unwrap();
        let eth0_addr = addr_list("eth0".try_as_index().unwrap().unwrap(), FAMILY_V4).unwrap().first().unwrap().ipnet.ip().clone();
        let mac_addr = new_hardware_addr().unwrap();
        let link = Link {
            link_attrs: LinkAttrs {
                mtu: 1500 - 60,
                name: "vxlan0".to_string(),
                hardware_addr: Some(mac_addr),
                ..Default::default()
            },
            link_kind: LinkKind::Vxlan(Vxlan {
                vxlan_id: 1,
                vtep_dev_index: eth0_link.link_attrs.index,
                src_addr: Some(eth0_addr),
                learning: true,
                port: 9999,
                gbp: false,
                ..Default::default()
            }),
        };
        let result = link_add(&link).unwrap();
    }


    pub fn new_hardware_addr() -> anyhow::Result<MacAddr6> {
        let mut rng = rand::thread_rng();
        let mut hardware_addr = [0u8; 6];
        rng.fill(&mut hardware_addr);
        hardware_addr[0] = (hardware_addr[0] & 0xfe) | 0x02;
        Ok(MacAddr6::from(hardware_addr))
    }

    #[test]
    fn test_rand_mac() -> anyhow::Result<()> {
        let mac = new_hardware_addr()?.into_array();
        println!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        // println!("{:?}", mac);
        Ok(())
    }
}
