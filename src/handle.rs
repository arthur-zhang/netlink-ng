use std::io::ErrorKind;

use anyhow::{anyhow, bail};
use bytes::BytesMut;
use log::{debug, error, info};
use netlink_packet_core::{
    NetlinkBuffer, NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NLM_F_ACK,
    NLM_F_MULTIPART, NLM_F_REQUEST,
};
use netlink_packet_route::RtnlMessage;
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::SocketAddr;

use crate::{link_by_name, LinkId};

pub struct NetlinkHandle {
    seq: u32,
    socket: netlink_sys::Socket,
}

impl NetlinkHandle {
    pub fn new() -> NetlinkHandle {
        let mut socket = netlink_sys::Socket::new(NETLINK_ROUTE).unwrap();
        socket.bind(&SocketAddr::new(0, 0)).unwrap();
        Self { seq: 0, socket }
    }
}

const INITIAL_READER_CAPACITY: usize = 64 * 1024;

impl NetlinkHandle {
    pub fn execute(&mut self, msg: RtnlMessage, flags: u16) -> anyhow::Result<Vec<RtnlMessage>> {
        self.send(msg, flags)?;
        self.recv()
    }

    fn send(&mut self, msg: RtnlMessage, flags: u16) -> anyhow::Result<()> {
        let mut packet = NetlinkMessage::from(msg);
        self.seq += 1;
        packet.header.sequence_number = self.seq;
        packet.header.flags = flags | NLM_F_REQUEST | NLM_F_ACK;
        packet.finalize();

        let mut bytes = vec![0u8; 8192];
        packet.serialize(&mut bytes);
        self.socket
            .send(&bytes, 0)
            .map_err(|e| anyhow!(e))?;
        Ok(())
    }

    fn decode<T>(src: &mut BytesMut) -> std::io::Result<Option<NetlinkMessage<T>>>
        where
            T: NetlinkDeserializable,
    {
        loop {
            if src.is_empty() {
                return Ok(None);
            }

            loop {
                // If there's nothing to read, return Ok(None)
                if src.is_empty() {
                    return Ok(None);
                }

                // This is a bit hacky because we don't want to keep `src`
                // borrowed, since we need to mutate it later.
                let len = match NetlinkBuffer::new_checked(src.as_ref()) {
                    Ok(buf) => buf.length() as usize,
                    Err(e) => {
                        // We either received a truncated packet, or the
                        // packet if malformed (invalid length field). In
                        // both case, we can't decode the datagram, and we
                        // cannot find the start of the next one (if
                        // any). The only solution is to clear the buffer
                        // and potentially lose some datagrams.
                        error!(
                            "failed to decode datagram, clearing buffer: {:?}: {:#x?}.",
                            e,
                            src.as_ref()
                        );
                        src.clear();
                        return Ok(None);
                    }
                };

                let bytes = src.split_to(len);

                let parsed = NetlinkMessage::<T>::deserialize(&bytes);
                match parsed {
                    Ok(packet) => {
                        return Ok(Some(packet));
                    }
                    Err(e) => {
                        error!("failed to decode packet {:#x?}: {}", &bytes, e);
                        // continue looping, there may be more datagrams in the
                        // buffer
                    }
                }
            }
        }
    }
    fn next_msg<T>(&self, mut src: &mut BytesMut) -> anyhow::Result<Option<NetlinkMessage<T>>>
        where
            T: NetlinkDeserializable,
    {
        loop {
            match Self::decode::<T>(&mut src) {
                Ok(Some(msg)) => {
                    return Ok(Some(msg));
                }
                Ok(None) => {}
                Err(e) => {
                    debug!("decode error: {:?}", e);
                    return Ok(None);
                }
            }
            src.clear();
            src.reserve(INITIAL_READER_CAPACITY);
            self.socket
                .recv(&mut src, 0)
                .map_err(|_| anyhow!("IO Error"))?;
        }
    }
    fn recv(&mut self) -> anyhow::Result<Vec<RtnlMessage>> {
        let mut result = Vec::new();
        let mut src = BytesMut::with_capacity(INITIAL_READER_CAPACITY);

        while let Ok(Some(msg)) = self.next_msg(&mut src) {
            if msg.header.sequence_number != self.seq {
                // ignore old packet msg
                if msg.header.sequence_number < self.seq {
                    continue;
                }
                bail!("seq not match: {} != {}", msg.header.sequence_number, self.seq);
            }
            // info!("recv: {:?}", &format!("{:?}", msg)[0..150]);
            let is_multi = (msg.header.flags & NLM_F_MULTIPART) != 0;
            match msg.payload {
                NetlinkPayload::Done(_) => {
                    // info!("recv done....");
                    return Ok(result);
                }
                NetlinkPayload::Error(e) => {
                    if let Some(code) = e.code {
                        if code.get() == -19 {
                            Err(std::io::Error::from(ErrorKind::NotFound))?
                        }
                        if code.get() == -17 {
                            info!(">>>>>>>>>>> code: {:?}", code);
                            Err(std::io::Error::from(ErrorKind::AlreadyExists))?
                        }
                        bail!("netlink: error response {}", e);
                    }
                    // info!("recv error empty....");
                    return Ok(result);
                }
                NetlinkPayload::Noop => {
                    bail!("unimplemented type: loop");
                }
                NetlinkPayload::Overrun(_) => {
                    bail!("unimplemented type: overrun");
                }
                NetlinkPayload::InnerMessage(msg) => {
                    result.push(msg);
                    if !is_multi {
                        return Ok(result);
                    }
                }
                _ => {
                    bail!("unimplemented type: {:?}", msg.payload)
                }
            }
        }

        return Ok(result);
    }
}

pub(crate) fn get_link_index(link: &LinkId) -> anyhow::Result<u32> {
    let index = match link {
        LinkId::Id(id) => *id,
        LinkId::Name(name) => {
            if let Some(it) = link_by_name(name)? {
                it.attrs().index
            } else {
                bail!("link not found: {}", name);
            }
        }
    };
    return Ok(index);
}
