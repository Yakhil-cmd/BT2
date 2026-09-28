### Title
Pool revenue is permanently frozen when the fixed Ownable owner (the controller) is blacklisted or deauthorized by the asset issuer - (File: contracts/pool/src/ops/revenue.rs)

### Summary
The Sparkn bug class is "a protocol-critical payout is hard-wired to a single recipient that cannot be changed, so a token-issuer blacklist of that recipient bricks the transfer and traps funds." XOXNO Lending has the same shape in the pool's revenue path: `claim_revenue` burns revenue shares and transfers the proceeds to `ownable::get_owner`, and the pool's owner is fixed at deploy to the deploying controller with no transfer/accept/renounce on the ABI. On Stellar, SAC and SEP-41 assets can deauthorize or clawback-gate any address — including contract addresses — so if the pool owner address is ever deauthorized/blacklisted for a market asset, `transfer_out` reverts and every claim on that market reverts, permanently freezing accrued protocol revenue.

### Finding Description
`ops::revenue::apply` in `contracts/pool/src/ops/revenue.rs` resolves the claim and then sends `actual_amount` to the Ownable owner:

```rust
let owner = ownable::get_owner(env)
    .unwrap_or_else(|| panic_with_error!(env, GenericError::OwnerNotSet));
outcome.cache.transfer_out(&owner, outcome.mutation.actual_amount);
``` [1](#0-0) 

Two properties make this the same root cause as the immutable `STADIUM_ADDRESS` finding:

1. **The recipient is immutable.** The pool is deployed with `deploy_v2(wasm_hash, (env.current_contract_address(),))`, so the owner is the controller address fixed at construction; the README states "the owner is fixed at deploy. There is no transfer, accept, or renounce on the ABI — migration goes through `upgrade`" (`contracts/pool/README.md` "Trust" section). Even a controller migration cannot retarget it: a newly deployed controller has a new address while each pool keeps paying the old one.

2. **The claim itself does the transfer in the same call.** `accounting` burns claimable revenue shares via `cache.burn_claimable_revenue()`, debits cash, commits, and `apply` transfers in the same transaction. If the token's transfer to the owner reverts (issuer deauthorization/clawback gating), the entire claim reverts — revenue shares are not burned, but the revenue can never exit the pool. This is already proven possible in-repo: `tests/test-harness/tests/controller/liqvid_rwa_collateral.rs` shows `claim_revenue` reverting with `ACCOUNT_NOT_ALLOWED` when the controller is not allowlisted by a gated trustline asset.

The unprivileged reachability holds: controller `claim_revenue(caller, assets)` requires only caller authorization ("Authority: None" in `docs/reference/endpoints.md`), and `claim_revenue_for_asset` in `contracts/controller/src/markets.rs` calls `pool_claim_revenue_call` which executes the reverting owner transfer.

Note the onward controller→accumulator leg does *not* have this problem (the accumulator is updatable via `set_accumulator`); the vulnerability is specifically the pool→owner leg, where the recipient can never change.

### Impact Explanation
Permanent freezing of unclaimed yield. Protocol revenue (accrued interest margin, withdrawal protocol fees, `seize_positions` deposit→revenue bookings, Credit-mode liquidation fees) can only ever leave the pool through `claim_revenue` → `transfer_out(owner)`. If the asset issuer deauthorizes or blacklists the pool owner address — plausible for regulated RWA/clawback-enabled assets already contemplated by the test suite — all revenue for that market is locked in the pool contract forever. No rescue path exists: the owner is immutable, the controller cannot sweep pool balances, and `upgrade` preserves the contract address. User supply/borrow funds are unaffected; the frozen funds are protocol revenue.

### Likelihood Explanation
Conditional on an external token-issuer action, same as the source finding. It requires a market whose asset enforces authorization/clawback (Stellar `AUTH_REQUIRED`/`AUTH_REVOCABLE` trustlines, or tokens with allowlists — the harness explicitly tests such gated assets) to revoke or deny the controller's authorization after pools are deployed. Unlike the updatable `accumulator`, the pool owner can never be rotated, so a single issuer action permanently bricks the path for every market on that asset. Medium severity: impact is limited to protocol revenue (not user principal), but the freeze is unrecoverable once triggered.

### Recommendation
Allow the pool's revenue recipient to be updated, mirroring the source report's recommendation:
- Add an owner-only (controller-authorized) or governance-timelocked `set_revenue_recipient`/`transfer_ownership` path on the pool, or have `claim_revenue` accept a recipient argument supplied by the controller so the already-updatable `accumulator` becomes the sole destination.
- Alternatively, make `claim_revenue` tolerant of a failed payout: return the burned revenue to the revenue share balance (skip `transfer_out` on failure via `try_transfer`) so revenue remains claimable once the owner is un-blacklisted — noting this still leaves no recovery if the owner can never receive.
- If the owner is ever made non-immutable, account for storage layout compatibility on upgrade, as the original report warns.

### Proof of Concept
Conceptual, mirroring `lqv_revenue_claim_needs_the_controller_and_accumulator_allowlisted` in `tests/test-harness/tests/controller/liqvid_rwa_collateral.rs`:

1. Governance creates a pool market for a clawback-enabled/`AUTH_REVOCABLE` asset (e.g., an RWA token); the controller is set as the pool's Ownable owner at deploy.
2. Users supply and borrow; `update_indexes` accrues positive `revenue` (or a `seize_positions`/`claim` liquidation books seized shares as revenue).
3. The asset issuer revokes the controller contract's trustline authorization (issuer-side `set_authorized(controller, false)`), or the controller is denylisted.
4. Any unprivileged caller invokes `controller.claim_revenue(caller, [hub_asset])`. Inside `claim_revenue_for_asset`, `pool_claim_revenue_call` reaches `revenue::apply`, and `cache.transfer_out(&owner, amount)` reverts with `ACCOUNT_NOT_ALLOWED` because the owner is the deauthorized controller.
5. The claim always reverts. The revenue shares remain, but there is no code path to change the pool's owner or to pay a different recipient — revenue for that market is permanently frozen in the pool, and the only "fix" (re-deploying the controller) does not help because pools keep paying the original owner address.

### Citations

**File:** contracts/pool/src/ops/revenue.rs (L22-35)
```rust
pub(crate) fn apply(env: &Env, hub_asset: HubAssetKey) -> PoolAmountMutation {
    let outcome = accounting(env, hub_asset);

    if outcome.mutation.actual_amount != 0 {
        let owner = ownable::get_owner(env)
            .unwrap_or_else(|| panic_with_error!(env, GenericError::OwnerNotSet));
        outcome
            .cache
            .transfer_out(&owner, outcome.mutation.actual_amount);
    }

    events::emit_market_state(env, outcome.cache.snapshot());
    outcome.mutation
}
```
