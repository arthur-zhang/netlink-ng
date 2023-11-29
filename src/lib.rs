pub use addr::*;
pub use link::*;
pub use route::*;

mod link;
mod addr;
pub mod handle;
pub mod nl_linux;
pub mod nl_type;
mod route;
mod utils;
mod rtnl_msg_ext;
mod neigh;
pub use neigh::*;

pub use libc::*;
pub use route::types::*;

#[macro_export]
macro_rules! unwrap_enum {
    ($e:expr, $variant:path) => {
        match $e {
            $variant(val) => Some(val),
            _ => None,
        }
    };
}