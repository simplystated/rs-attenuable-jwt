#![doc = include_str!("../README.md")]

pub mod protocol;
pub mod sign;
pub mod verify;

#[cfg(any(feature = "ed25519", feature = "integration-test", test))]
pub mod ed25519;
