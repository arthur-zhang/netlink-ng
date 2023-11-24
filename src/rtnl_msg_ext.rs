use netlink_packet_route::link::nlas::Nla;
pub use netlink_packet_route::RtnlMessage;

pub fn index(msg: &RtnlMessage) -> u32 {
    match &msg {
        RtnlMessage::NewLink(inner)
        | RtnlMessage::DelLink(inner)
        | RtnlMessage::GetLink(inner)
        | RtnlMessage::SetLink(inner)
        | RtnlMessage::NewLinkProp(inner)
        | RtnlMessage::DelLinkProp(inner) => inner.header.index,
        _ => {
            unimplemented!()
        }
    }
}

pub fn flags(msg: &RtnlMessage) -> u32 {
    match &msg {
        RtnlMessage::NewLink(inner)
        | RtnlMessage::DelLink(inner)
        | RtnlMessage::GetLink(inner)
        | RtnlMessage::SetLink(inner)
        | RtnlMessage::NewLinkProp(inner)
        | RtnlMessage::DelLinkProp(inner) => inner.header.flags,
        _ => {
            unimplemented!()
        }
    }
}

pub fn link_layer_type(msg: &RtnlMessage) -> u16 {
    match &msg {
        RtnlMessage::NewLink(inner)
        | RtnlMessage::DelLink(inner)
        | RtnlMessage::GetLink(inner)
        | RtnlMessage::SetLink(inner)
        | RtnlMessage::NewLinkProp(inner)
        | RtnlMessage::DelLinkProp(inner) => inner.header.link_layer_type,
        _ => {
            unimplemented!()
        }
    }
}

pub fn attrs(msg: &RtnlMessage) -> &Vec<Nla> {
    match &msg {
        RtnlMessage::NewLink(inner)
        | RtnlMessage::DelLink(inner)
        | RtnlMessage::GetLink(inner)
        | RtnlMessage::SetLink(inner)
        | RtnlMessage::NewLinkProp(inner)
        | RtnlMessage::DelLinkProp(inner) => &inner.nlas,
        _ => {
            unimplemented!()
        }
    }
}
    