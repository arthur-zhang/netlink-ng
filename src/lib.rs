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
#[macro_export]
macro_rules! unwrap_enum {
    ($e:expr, $variant:path) => {
        match $e {
            $variant(val) => Some(val),
            _ => None,
        }
    };
}