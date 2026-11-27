//! Enrichment: OUI vendor lookup, device-type inference, threat intel.

pub mod classify;
pub mod oui;
pub mod ti;

pub use classify::{classify, Context};
pub use oui::OuiDb;

use relay_core::Device;

/// Build the enrichment callback handed to `Store::ingest`.
pub fn enricher<'a>(oui: &'a OuiDb, ctx: &'a Context) -> impl Fn(&mut Device) + 'a {
    move |d: &mut Device| {
        if d.vendor.is_none() && !d.mac_randomized {
            d.vendor = oui.lookup(&d.mac).map(str::to_string);
        }
        d.device_type = classify(d, ctx);
    }
}
