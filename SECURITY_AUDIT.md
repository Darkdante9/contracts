# Security Review — SynapsVault Contracts

**Scope:** `vault-registry`, `access-lease`, `subscription` — initialisation,
access control, expiry arithmetic, revocation, cancellation and the upgrade
entrypoints.
**Status:** All High and Medium findings below are resolved in the current code.

Each finding lists its severity, the issue, and how it is resolved. Every
resolution is covered by a unit test in the contract's test module.

---

## 1. Findings

| ID | Contract | Severity | Finding | Resolution | Status |
|---|---|---|---|---|---|
| SV-1 | access-lease, subscription | **Critical** | `init` could be called again by anyone after deployment, overwriting the admin and taking over every admin-only entrypoint (grant/revoke leases, subscribe/renew, `upgrade`). | `init` fails with `AlreadyInitialised` once an admin is set. Test: `init_twice_is_rejected`. | Resolved |
| SV-2 | subscription | **Critical** | `create_plan` overwrote an existing plan, letting any address re-create someone else's `plan_id` with itself as publisher and change the price. | `create_plan` fails with `PlanExists` for an existing id. Test: `existing_plan_cannot_be_hijacked`. | Resolved |
| SV-3 | vault-registry | Medium | Re-calling `init` returned the misleading `AlreadyRegistered` error. | New `AlreadyInitialised` error code. | Resolved |
| SV-4 | access-lease | High | `expires_at = now + duration` could overflow `u32`. With `overflow-checks` it aborted the call; without it would wrap to a past ledger. | `checked_add`; overflow returns `InvalidDuration`. Test: `overflowing_duration_rejected`. | Resolved |
| SV-5 | subscription | Medium | Period-end arithmetic (`+ CYCLE`) was unchecked. | `checked_add`; overflow returns `Overflow`. | Resolved |
| SV-6 | access-lease | Medium | `grant_lease` accepted `duration_ledgers = 0`; `extend_lease` accepted `0`. | Both reject zero with `InvalidDuration`. Test: `zero_duration_rejected`. | Resolved |
| SV-7 | access-lease, subscription | Medium | No admin rotation — a compromised admin key required a redeploy. | Admin-gated `set_admin`. Test: `set_admin_rotates_admin`. | Resolved |
| SV-8 | subscription | Medium | `is_active` returned `false` immediately on `cancel`, contradicting the documented "access until period end" behaviour and cutting off paid access. | `is_active` depends only on `current_period_end`; `cancelled` blocks renewals. Re-subscribing carries over remaining paid time. Tests: `cancel_keeps_access_until_period_end_and_blocks_renewal`, `resubscribe_after_cancel_carries_over_paid_time`. | Resolved |
| SV-9 | subscription | Low | `deactivate_plan` and `cancel` wrote entries without bumping their TTL, so entries could be archived. | TTL bumped on every write. | Resolved |
| SV-10 | all | Low | access-lease and subscription emitted no events, so there was no on-chain audit trail for grants, revocations, subscriptions or upgrades. | Events on every state change and on `upgrade` (see `docs/CONTRACTS.md`). | Resolved |
| SV-11 | access-lease, subscription | Low | Instance storage (holding the admin) was only bumped at `init` and could expire. | Instance TTL bumped on every admin-gated call. | Resolved |
| SV-12 | access-lease | High | `init` did not require the admin's signature, so a front-runner could call `init` first after deployment and install themselves as admin, taking over every admin-only entrypoint. | `init` calls `admin.require_auth()` before writing any state, so only the intended admin can initialise the contract. Test: `init_requires_admin_auth`. | Resolved |

## 2. Access-control matrix (verified by tests)

| Entrypoint | Required signer | Non-signer test |
|---|---|---|
| `vault-registry::register` | `creator` | `mutations_require_creator_auth` |
| `vault-registry::set_price` etc. | stored creator | `set_price_by_non_creator_is_rejected` |
| `vault-registry::upgrade` | admin | `upgrade_rejects_non_admin` |
| `access-lease::init` | admin | `init_requires_admin_auth` |
| `access-lease::grant_lease` / `extend_lease` / `revoke_lease` | admin | `grant_by_non_admin_is_rejected` |
| `subscription::subscribe` / `renew` | admin | `subscribe_by_non_admin_is_rejected` |
| `subscription::deactivate_plan` | publisher | `deactivate_requires_publisher_auth` |
| `subscription::cancel` | subscriber | `cancel_keeps_access_until_period_end_and_blocks_renewal` |

## 3. Expiry semantics

- Time is measured in ledger sequence numbers, which are monotonic, so clock
  skew does not apply.
- A lease / subscription is valid while `end > ledger.sequence()`; on the
  ledger equal to `end` it is expired (tests: `lease_expires_exactly_at_expiry`
  and the cancellation test above).
- Soroban has no re-entrancy into the same contract, and none of these
  contracts make cross-contract calls.

## 4. Residual risk

- **Admin key compromise.** The admin can upgrade code and grant arbitrary
  leases. Use a hardware-backed or multisig account on mainnet and rotate with
  `set_admin` if needed.
- **Upgrades do not migrate data.** Storage layout changes require an explicit
  migration step (see README → Upgrades).
