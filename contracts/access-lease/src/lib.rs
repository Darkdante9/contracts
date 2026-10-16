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
    /// Reserved; kept so existing error codes stay stable.
    UpgradeNotAllowed = 6,
    /// `init` has already been called; the admin cannot be overwritten.
    AlreadyInitialised = 7,
    /// The lease has already expired; there is nothing to revoke.
    LeaseExpired = 8,
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
    /// * `resource_id` — identifier of the resource being leased.
    /// * `buyer` — wallet receiving access.
    /// * `duration_ledgers` — lease length in ledgers; must be non-zero.
    ///
    /// # Errors
    /// * [`Error::NotInitialised`] — `init` has not been called.
    /// * [`Error::InvalidDuration`] — `duration_ledgers == 0`, or the expiry
    ///   would overflow `u32`.
    /// * [`Error::AlreadyActive`] — an unexpired lease already exists for the
    ///   `(resource_id, buyer)` pair.
    pub fn grant_lease(
        env: Env,
        resource_id: String,
        buyer: Address,
        duration_ledgers: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env)?;
        if duration_ledgers == 0 {
            return Err(Error::InvalidDuration);
        }
        let now = env.ledger().sequence();
        let expires_at = now.checked_add(duration_ledgers).ok_or(Error::InvalidDuration)?;
        let key = DataKey::Lease(resource_id.clone(), buyer.clone());
        if let Some(existing) = env.storage().persistent().get::<_, Lease>(&key) {
            if existing.expires_at > now {
                return Err(Error::AlreadyActive);
            }
        }
        let lease = Lease {
            resource_id: resource_id.clone(),
            buyer: buyer.clone(),
            granted_at: now,
            expires_at,
            duration_ledgers,
        };
        env.storage().persistent().set(&key, &lease);
        env.storage().persistent().extend_ttl(&key, BUMP_THRESH, BUMP);
        GrantEvent {
            resource_id,
            buyer,
            expires_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Extend an existing lease's expiry by `additional_ledgers`.
    ///
    /// Admin-only. The lease must exist; extending an expired lease is allowed
    /// and revives it from the current ledger sequence.
    ///
    /// # Errors
    /// * [`Error::NotInitialised`] — `init` has not been called.
    /// * [`Error::LeaseNotFound`] — no lease exists for the pair.
    /// * [`Error::InvalidDuration`] — `additional_ledgers == 0`, or the new
    ///   expiry would overflow `u32`.
    pub fn extend_lease(
        env: Env,
        resource_id: String,
        buyer: Address,
        additional_ledgers: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env)?;
        if additional_ledgers == 0 {
            return Err(Error::InvalidDuration);
        }
        let key = DataKey::Lease(resource_id.clone(), buyer.clone());
        let mut lease = env
            .storage()
            .persistent()
            .get::<_, Lease>(&key)
            .ok_or(Error::LeaseNotFound)?;
        let now = env.ledger().sequence();
        let base = if lease.expires_at > now {
            lease.expires_at
        } else {
            now
        };
        let expires_at = base
            .checked_add(additional_ledgers)
            .ok_or(Error::InvalidDuration)?;
        lease.expires_at = expires_at;
        lease.duration_ledgers = lease.duration_ledgers.saturating_add(additional_ledgers);
        env.storage().persistent().set(&key, &lease);
        env.storage().persistent().extend_ttl(&key, BUMP_THRESH, BUMP);
        ExtendEvent {
            resource_id,
            buyer,
            expires_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Revoke an existing lease, removing the buyer's access immediately.
    ///
    /// Admin-only. The lease record is deleted from persistent storage and a
    /// [`RevokeEvent`] is emitted.
    ///
    /// An already-expired lease is treated as an explicit **no-op**: the
    /// record is removed (if still present) but no [`RevokeEvent`] is emitted,
    /// since the lease no longer grants any access and there is nothing to
    /// revoke. This keeps the event log meaningful — a `RevokeEvent` always
    /// signals that access was actually terminated by this call.
    ///
    /// # Errors
    /// * [`Error::NotInitialised`] — `init` has not been called.
    /// * [`Error::LeaseNotFound`] — no lease exists for the pair.
    pub fn revoke_lease(env: Env, resource_id: String, buyer: Address) -> Result<(), Error> {
        Self::require_admin(&env)?;
        let key = DataKey::Lease(resource_id.clone(), buyer.clone());
        let lease = env
            .storage()
            .persistent()
            .get::<_, Lease>(&key)
            .ok_or(Error::LeaseNotFound)?;
        env.storage().persistent().remove(&key);
        // Already-expired leases grant no access: treat revocation as a no-op
        // and skip the event so `RevokeEvent` only fires on real revocations.
        if lease.expires_at <= env.ledger().sequence() {
            return Ok(());
        }
        RevokeEvent {
            resource_id,
            buyer,
        }
        .publish(&env);
        Ok(())
    }

    /// Return the stored lease for `(resource_id, buyer)`, if any.
    ///
    /// Permissionless. The returned lease may be expired; callers should
    /// compare `expires_at` against the current ledger sequence (or use
    /// [`is_valid`](AccessLease::is_valid)) to determine access.
    pub fn get_lease(env: Env, resource_id: String, buyer: Address) -> Option<Lease> {
        env.storage()
            .persistent()
            .get(&DataKey::Lease(resource_id, buyer))
    }

    /// Return `true` if an unexpired lease exists for `(resource_id, buyer)`.
    ///
    /// Permissionless. A lease is valid while
    /// `expires_at > env.ledger().sequence()`.
    pub fn is_valid(env: Env, resource_id: String, buyer: Address) -> bool {
        match env
            .storage()
            .persistent()
            .get::<_, Lease>(&DataKey::Lease(resource_id, buyer))
        {
            Some(lease) => lease.expires_at > env.ledger().sequence(),
            None => false,
        }
    }

    /// Upgrade the contract WASM. Admin-only.
    ///
    /// # Errors
    /// * [`Error::NotInitialised`] — `init` has not been called.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        Self::require_admin(&env)?;
        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        UpgradeEvent { new_wasm_hash }.publish(&env);
        Ok(())
    }

    /// Internal helper: require the configured admin's auth, or fail.
    fn require_admin(env: &Env) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialised)?;
        admin.require_auth();
        Ok(())
    }
}
