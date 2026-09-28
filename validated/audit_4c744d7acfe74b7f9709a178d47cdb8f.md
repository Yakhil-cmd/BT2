### Title
Unbounded dust-account spam via `supply(account_id=0)` with no minimum deposit - (File: contracts/controller/src/positions/supply.rs)

### Summary
The controller's `supply` entrypoint creates a brand-new account (position NFT + persistent `AccountMeta` + position-map entries) for any `account_id == 0` call, and accepts a deposit of a single base unit (`amount = 1`) because there is no minimum-deposit or dust floor anywhere in the deposit path. A single unprivileged address can therefore mint an unbounded number of permanent accounts at near-zero token cost, mirroring the `ipfs-bitswap` DoS class: attacker-controlled insertion of unwanted entries into shared persistent storage.

### Finding Description
- `process_supply` calls `account::load_or_create_account`, which unconditionally creates a new account whenever `account_id == 0` (`contracts/controller/src/account.rs:95-97`). `create_account_with` mints a position NFT and writes `AccountMeta` to persistent storage (`contracts/controller/src/account.rs:62-73`).
- `process_deposit` only requires each leg to be positive (`aggregate_positive_payments`, `transfer_amount_measured` with `AmountMustBePositive`); a `1`-unit deposit passes every gate (`contracts/controller/src/positions/supply.rs:48,116-125`).
- Each iteration adds durable ledger entries across two contracts (controller `AccountMeta`/position maps and the position-NFT ownership record). IDs are never reused, and an account holding a nonzero dust position cannot be removed by anyone except its owner, so the spammed entries persist indefinitely (`skills/xoxno-lending-contracts/positions.md` documents deletion only when both maps are empty, via owner-gated `withdraw`).
- The repo's own test `poc_single_actor_spams_unbounded_dust_accounts` demonstrates 64 accounts created by one actor with `amount = 1` each, all persisting (`tests/test-harness/tests/controller/supply.rs:313-344`).
- There is no per-owner account cap; `validate_bulk_position_limits` caps positions *within* an account, not the number of accounts (`contracts/controller/src/risk/validation.rs:65-111`).

### Impact Explanation
Every spammed account inflates the controller's and position-NFT's persistent ledger footprint. On Soroban, persistent entries carry ongoing rent/TTL obligations: renewal costs for protocol-maintained entries grow, `renew_account`/archival-restore surface expands, and state-scanning operations become progressively more expensive. This is a permanent, irreversible state bloat paid for with dust — the classic resource-exhaustion pattern of the advisory, realized as ledger-state exhaustion rather than blockstore exhaustion. The attacker's cost scales linearly but trivially (1 base unit of a low-value asset plus fees per account), while the storage burden is borne by the shared contract state forever.

### Likelihood Explanation
Fully permissionless: `supply` requires only `caller.require_auth()` and a positive transfer. No governance listing, threshold, or minimum blocks a 1-unit deposit, and each call must create a fresh account by design (`account_id == 0` → `create_account`). Any address holding a trivial token balance can execute the loop in the PoC. Limitation: per-transaction ledger-write limits bound accounts per tx, so the attack is a sustained trickle rather than a single burst, and it does not directly steal or freeze user funds — it degrades the protocol's storage economics, consistent with Medium severity.

### Recommendation
- Enforce a minimum initial deposit (in asset units or USD value via the existing `Context` price cache) before `create_account` is allowed, i.e., reject `account_id == 0` supplies whose measured receipt is below a floor.
- Alternatively, allow dust supply only into an existing `account_id != 0`, or cap the number of accounts owned by a single address.
- Consider a permissionless cleanup path for sub-dust accounts so abandoned spam entries can be removed.

### Proof of Concept
```rust
// tests/test-harness/tests/controller/supply.rs:313-344 (existing repo test)
let attacker = t.get_or_create_user("attacker");
usdc.token_admin.mint(&attacker, &(N as i128)); // N base units total
for _ in 0..N {
    let dust = vec![&t.env, (hub_asset(asset.clone()), 1i128)];
    let id = ctrl.supply(&attacker, &0u64, &1u32, &dust); // amount = 1, account_id = 0
    assert!(id > last_id);            // new account each call
    assert!(ctrl.account_exists(&id)); // persists in storage
    last_id = id;
}
```
Each iteration mints a position NFT and writes `AccountMeta` + position-map entries that no third party can remove, at a cost of 1 base unit of USDC per account.