//! The part of adbData that knows about adb and Android, kept apart from the window so every rule
//! can be tested against a simulated adb server (`fake`).
//!
//! adbData talks to the adb server the way adb itself does: one TCP connection to the server
//! (`wire`), switched to a phone and then to its file service (`sync`). A whole folder copies over
//! that one connection, without starting a program per file.

pub mod devices;
pub mod fake;
pub mod fetch;
pub mod history;
pub mod names;
pub mod phone;
pub mod plan;
pub mod remote;
pub mod runner;
pub mod sync;
pub mod tools;
pub mod transfer;
pub mod wire;
