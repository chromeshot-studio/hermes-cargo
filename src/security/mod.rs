//! Module 3 - the security and sandboxing engine.
//!
//! Everything an update touches passes through here first:
//!
//! * [`crypto`]   - Ed25519 manifest verification, streaming SHA-256,
//!                  rollback protection.
//! * [`safepath`] - Zip-Slip prevention: strict path canonicalisation,
//!                  symlink refusal, archive limits.
//! * [`consent`]  - declared folder scope, enforced then confirmed by the user.
//!
//! The guiding assumption is that the studio's CDN is *not* trusted. It serves
//! bytes; the pinned key in the user's `.origin` file decides whether those
//! bytes mean anything.

pub mod consent;
pub mod crypto;
pub mod safepath;
