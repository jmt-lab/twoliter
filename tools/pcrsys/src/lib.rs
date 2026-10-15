//! PCR prediction library for Bottlerocket.
//!
//! Predicts TPM Platform Configuration Register (PCR) values based on
//! boot components, EFI variables, and GPT partition tables. The disk, GPT,
//! filesystem, and PE helpers are also used by other tools such as reprosys.

pub mod aws;
pub mod diskfs;
pub mod efi;
pub mod error;
pub mod gpt;
pub mod parsers;
pub mod pcrs;
pub mod pe;
pub mod platform;
pub mod predict;
