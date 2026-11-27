//! Data model, SQLite store and risk engine.
//!
//! Connection status, risk level and confidence are deliberately kept as
//! separate fields: a device can be `Online` and `Red` at the same time.

pub mod i18n;
pub mod mac;
pub mod model;
pub mod risk;
pub mod store;

pub use i18n::Lang;
pub use mac::Mac;
pub use model::*;
pub use store::Store;
