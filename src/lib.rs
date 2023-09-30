//! # Example
//! ```rust
#![doc = include_str!("./bin/ecfuzz.rs")]
//! ```
//!
#![doc = include_str!("../readme.md")]

pub mod config;

pub mod corpus;

pub mod execute;

pub mod grammar_tree;

pub mod mutator;
