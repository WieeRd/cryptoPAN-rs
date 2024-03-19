// DOC: add #![deny(missing_doc)] and start working on the documentation

pub mod backends;
pub mod scramble;

pub use scramble::{Encrypter, Scrambler};
