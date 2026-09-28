### Title
Permissionless third-party supply top-up can indefinitely block `clean_bad_debt` on an insolvent account - ([File: contracts/controller/src/positions/supply.rs])

### Summary
The external report's bug class — anyone may grow a foreign position without the owner's consent — maps directly onto XOXNO Lending: `controller::supply` is permissionless for existing supply legs of any account (`require_third_party_existing_supply` only forbids opening a *new* asset slot for a foreign account). Because `clean_bad_debt` is gated on the account's remaining collateral being at or below the dust threshold, an unprivileged attacker can repeatedly donate small top-ups to keep an insolvent account above that threshold, permanently blocking bad-debt socialization.

### Finding Description
`clean_bad_debt` may only socialize an insolvent account's residual debt "once its remaining collateral is at or below the dust threshold" (controller README, `liquidate`/`clean_bad_debt` table) and then removes the account and burns its NFT via `execute_bad_debt_cleanup` (`contracts/controller/src/positions/liquidation/bad_debt.rs:14-60`).

Meanwhile, `supply` requires only `caller.require_auth()` and, for a foreign `account_id`, only that each supplied `hub_asset` already exists in `account.supply_positions` (`contracts/controller/src/positions/supply.rs:78-97`). There is no health-factor, solvency, owner-consent, or minimum-amount check on the top-up path: `process_supply` calls `process_deposit`, which credits measured receipts into the victim's supply shares.

Sequence:

1. An account becomes insolvent (borrow > collateral) and its remaining collateral decays to/below the dust threshold, making it eligible for `clean_bad_debt`.
2. An attacker calls `supply(attacker, victim_account_id, victim_spoke_id, [(existing_hub_asset, dust + ε)])`. This is an existing-leg top-up, so `require_third_party_existing_supply` passes.
3. The account's collateral is now strictly above the dust threshold; every `clean_bad_debt` call reverts on the dust gate.
4. A liquidator may seize the donated collateral (HF < 1 is unchanged — the debt is still insolvent), after which the attacker re-tops-up, repeating indefinitely at cost ≈ one dust-threshold worth of tokens per round.

The invariants document the permissionless top-up (INV-AUTH-03), but they explicitly note "permissionless access does not imply that every operation preserves health or collateral value" and do not bless blocking bad-debt cleanup; INV-LIQ-04 assumes the dust cap is the only gate and cannot be held open by a stranger.

### Impact Explanation
Residual bad debt is never socialized: the supply-index write-down that `clean_bad_debt` performs is blocked, so the shortfall continues accruing interest inside the market instead of being crystallized. Suppliers' claims remain overstated (the debt is still on the books but unrecoverable), which is a protocol-insolvency / temporary-freezing-of-funds impact class: the market's accounting cannot reach its terminal cleanup state for as long as the griefer chooses to fund top-ups.

### Likelihood Explanation
Medium. The attacker spends real funds each round (the top-up is seizable by liquidators), so this is griefing with a per-round cost bounded by the dust threshold plus transfer fees, not free. However, dust thresholds are deliberately small, the attack requires no privilege, no timing, and no oracle manipulation, and can be automated by a contract. Any motivated party (e.g., a competitor, or an attacker wanting to keep a poisoned market alive to suppress the supply index dynamics) can sustain it.

### Recommendation
Gate third-party top-ups on the target account's state, not just slot existence. Concretely, in `require_third_party_existing_supply` (or `process_supply` before `process_deposit`), reject non-owner/non-delegate supply when the account is insolvent or when `account_id` is eligible for `clean_bad_debt` (collateral ≤ dust threshold and debt > 0). Alternatively, make `clean_bad_debt` accept an optional payer and count a measured donation toward the bad debt rather than toward collateral, or allow `clean_bad_debt` to seize collateral regardless of the dust cap once insolvency is proven.

### Proof of Concept
```rust
// Attacker BOB keeps ALICE's insolvent account above the dust threshold
// so clean_bad_debt always reverts.

// setup: ALICE supplied USDC and borrowed ETH; price moved so debt > collateral
// and remaining collateral <= dust threshold.
assert!(t.can_be_cleaned(ALICE)); // eligible for clean_bad_debt

// permissionless top-up of an EXISTING supply leg
t.try_supply_to_account(BOB, ALICE, "USDC", dust_plus_epsilon)
    .expect("third-party top-up of existing leg is permissionless");

// now cleanup is blocked
assert_contract_error(
    t.try_clean_bad_debt(ANYONE, ALICE),
    errors::BAD_DEBT_NOT_CLEANABLE, // dust-threshold gate
);

// after a liquidator seizes BOB's donation, repeat the same supply call.
```