#![no_std]
//! SynapsVault — Access Lease Contract (Soroban / Stellar)
//!
//! Issues time-limited on-chain access grants to vault resources.
//! Any third party can verify a buyer's access via `is_valid` without
//! trusting the SynapsVault backend — the Stellar ledger is the source of truth.

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN,
    ContractExecutable, Env, String,
};

const DAY: u32 = 17_280; // ~5s/ledger × 17280 = 1 day
const BUMP: u32 = 90 * DAY;
const BUMP_THRESH: u32 = BUMP - DAY;

/// Maximum accepted length (in bytes) of a `resource_id`.
///
/// Bounds the size of the persistent-storage key and the emitted event topics
/// so a caller cannot store or emit an unbounded identifier.
pub const MAX_RESOURCE_ID_LEN: u32 = 64;

/// Contract version, sourced from Cargo.toml at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A time-limited access grant issued to a buyer for a specific resource.
///
/// A lease is considered **active** (valid) while
/// `expires_at > env.ledger().sequence()`. Once the current ledger sequence
/// reaches or passes `expires_at`, the lease is expired and `is_valid`
/// returns `false`, even though the record may still be stored on-chain.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Lease {
    /// Opaque identifier of the vault resource the lease grants access to.
    pub resource_id: String,
    /// Wallet address entitled to access the resource while the lease is active.
    pub buyer: Address,
    /// Ledger sequence at which the lease was granted.
    pub granted_at: u32,
    /// Ledger sequence at which the lease stops being valid (exclusive).
    pub expires_at: u32,
    /// Length of the lease in ledgers, as originally requested.
    pub duration_ledgers: u32,
}

/// Storage keys used by the contract.
#[contracttype]
pub enum DataKey {
    /// Instance-storage key holding the admin [`Address`] set by
    /// [`AccessLease::init`]. Its presence is also the "initialised" flag.
    Admin,
    /// Persistent-storage key holding the [`Lease`] for a
    /// `(resource_id, buyer)` pair.
    Lease(String, Address),
    /// Instance-storage key holding the version recorded at `init`.
    Version,
}

/// Errors returned by the contract's fallible entry points.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// The caller is not the configured admin (or failed auth).
    NotAdmin = 1,
    /// No lease exists for the given `(resource_id, buyer)` pair.
    LeaseNotFound = 2,
    /// An unexpired lease already exists for the given pair.
    AlreadyActive = 3,
    /// The requested duration was zero or would overflow the ledger sequence.
    InvalidDuration = 4,
    /// `init` has not been called, so no admin is configured.
    NotInitialised = 5,
    /// `init` has already been called; the admin cannot be overwritten.
    AlreadyInitialised = 7,
    /// The lease has already expired; there is nothing to revoke.
    LeaseExpired = 8,
    /// `resource_id` is empty or exceeds [`MAX_RESOURCE_ID_LEN`] bytes.
    InvalidResourceId = 9,
}

/// Emitted by [`AccessLease::init`]. Topics: `("init",)`; data: admin.
#[contractevent(topics = ["init"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitEvent {
    pub admin: Address,
}

/// Emitted by [`AccessLease::set_admin`]. Topics: `("setadmin",)`; data: new admin.
#[contractevent(topics = ["setadmin"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetAdminEvent {
    pub new_admin: Address,
}

/// Emitted by [`AccessLease::grant_lease`]. Topics: `("grant", resource_id, buyer)`;
/// data: `expires_at`.
#[contractevent(topics = ["grant"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantEvent {
    #[topic]
    pub resource_id: String,
    #[topic]
    pub buyer: Address,
    pub expires_at: u32,
}

/// Emitted by [`AccessLease::extend_lease`]. Topics: `("extend", resource_id, buyer)`;
/// data: new `expires_at`.
#[contractevent(topics = ["extend"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendEvent {
    #[topic]
    pub resource_id: String,
    #[topic]
    pub buyer: Address,
    pub expires_at: u32,
}

/// Emitted by [`AccessLease::revoke_lease`]. Topics: `("revoke", resource_id, buyer)`;
/// no data.
#[contractevent(topics = ["revoke"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeEvent {
    #[topic]
    pub resource_id: String,
    #[topic]
    pub buyer: Address,
}

/// Emitted by [`AccessLease::upgrade`]. Topics: `("upgrade",)`; data: new WASM hash.
#[contractevent(topics = ["upgrade"], data_format = "single-value")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeEvent {
    pub new_wasm_hash: BytesN<32>,
}

#[contract]
pub struct AccessLease;

#[contractimpl]
impl AccessLease {
    /// Initialise the contract — set the admin wallet (backend platform wallet).
    ///
    /// Must be called once immediately after deployment. Stores `admin` under
    /// [`DataKey::Admin`] in instance storage and bumps the instance TTL.
    ///
    /// # Parameters
    /// * `admin` — the platform wallet authorised to perform admin-only
    ///   mutations ([`grant_lease`](AccessLease::grant_lease),
    ///   [`extend_lease`](AccessLease::extend_lease),
    ///   [`revoke_lease`](AccessLease::revoke_lease)).
    ///
    /// # Errors
    /// * [`Error::AlreadyInitialised`] — an admin is already set. Use
    ///   [`set_admin`](AccessLease::set_admin) to rotate it.
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialised);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Version, &String::from_str(&env, VERSION));
        env.storage().instance().extend_ttl(BUMP_THRESH, BUMP);
        InitEvent { admin }.publish(&env);
        Ok(())
    }

    /// Return the configured admin address.
    ///
    /// # Errors
    /// * [`Error::NotInitialised`] — `init` has not been called.
    pub fn admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialised)
    }

    /// Rotate the admin to `new_admin`. Requires the current admin's auth.
    ///
    /// # Errors
    /// * [`Error::NotInitialised`] — `init` has not been called.
    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().extend_ttl(BUMP_THRESH, BUMP);
        SetAdminEvent { new_admin }.publish(&env);
        Ok(())
    }

    /// Return the version recorded at `init`, falling back to the compiled
    /// version. Permissionless.
    pub fn get_version(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::Version)
            .unwrap_or_else(|| String::from_str(&env, VERSION))
    }

    /// Returns `true` if the stored version matches the compiled-in version.
    /// Used to detect stale deployments that need re-initialisation.
    pub fn is_compatible(env: Env) -> bool {
        match env.storage().instance().get::<_, String>(&DataKey::Version) {
            Some(stored) => stored == String::from_str(&env, VERSION),
            None => false,
        }
    }

    /// Grant a time-limited lease to `buyer` for `resource_id`.
    ///
    /// Admin-only: the configured admin must have authorised the call.
    ///
    /// # Parameters
    /// * `resource_id` — identifier of the resource being leased. Must be

/* … truncated 609 chars — edit only what you need near the top … */
