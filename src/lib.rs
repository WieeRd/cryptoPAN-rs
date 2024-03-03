// DOC: add #![deny(missing_doc)] and start working on the documentation

mod anonymize;
// mod deanonymize;

pub mod backends;

pub use anonymize::{Anonymizer, Encrypter};
// pub use deanonymize::{Deanonymizer, Decrypter};
