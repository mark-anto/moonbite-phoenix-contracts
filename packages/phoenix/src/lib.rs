#![no_std]

extern crate self as phoenix;

pub mod access_control;
pub mod utils;

pub use phoenix_macros::{authorized_by, no_access_control, with_access_control};
