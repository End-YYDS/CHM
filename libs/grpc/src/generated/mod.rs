#[cfg(any(feature = "crl-client", feature = "crl-server"))]
pub mod crl;

#[cfg(any(feature = "dns-client", feature = "dns-server"))]
pub mod dns;

#[cfg(any(feature = "ldap-client", feature = "ldap-server"))]
pub mod ldap;

#[cfg(any(feature = "ca-client", feature = "ca-server"))]
pub mod ca;

#[cfg(any(feature = "dhcp-client", feature = "dhcp-server"))]
pub mod dhcp;

#[cfg(any(feature = "controller-client", feature = "controller-server"))]
pub mod controller;

#[cfg(any(feature = "common-client", feature = "common-server"))]
pub mod common;

#[cfg(any(feature = "restful-client", feature = "restful-server"))]
pub mod restful;

