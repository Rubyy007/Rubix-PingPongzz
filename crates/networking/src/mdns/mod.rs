//! mDNS peer discovery (advertisement + browser).

pub mod advertiser;
pub mod browser;

pub use advertiser::MdnsAdvertiser;
pub use browser::{MdnsBrowser, DiscoveryEvent};