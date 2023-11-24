use std::net::IpAddr;
use anyhow::{anyhow, bail};

use netlink_packet_route::{AF_INET, AF_INET6};

use crate::nl_type::*;

pub fn ip_to_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
        IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
    }
}

pub fn ip_to_family(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => AF_INET as u8,
        IpAddr::V6(_) => AF_INET6 as u8,
    }
}

pub fn bytes_to_ip(bytes: &[u8], family: Family) -> anyhow::Result<IpAddr> {
    match family {
        FAMILY_V4 => {
            let mut ip = [0u8; 4];
            if bytes.len() < 4 {
                bail!("ipv4 bytes len < 4");
            }
            ip.copy_from_slice(&bytes[..4]);
            Ok(IpAddr::V4(ip.into()))
        }
        FAMILY_V6 => {
            let mut ip = [0u8; 16];
            if bytes.len() < 16 {
                bail!("ipv6 bytes len < 16");
            }
            ip.copy_from_slice(&bytes[..16]);
            Ok(IpAddr::V6(ip.into()))
        }
        _ => Err(anyhow!("invalid family: {}", family)),
    }
}
