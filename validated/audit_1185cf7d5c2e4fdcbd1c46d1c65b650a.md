### Title
Permissionless dust top-ups keep an insolvent account's collateral above the cleanup cap, indefinitely blocking `clean_bad_debt` - (File: contracts/controller/src/positions/supply.rs)

### Summary
`clean_bad_debt` is the only permissionless path that socializes an insolvent account's residual debt and deletes the account, and it is gated on the account's remaining collateral being at or below a dust cap. Separately, `supply` allows any third party to top up a *supply leg the account already holds*. An attacker can combine the two: whenever an insolvent account's collateral sits at/below the dust cap, the attacker supplies one minimal unit into an existing collateral leg, pushing collateral back above the cap and reverting every `clean_bad_debt` call. Repeated forever at negligible cost, the account can never be cleaned up — an on-chain analog of CVE-2024-55008's "attacker repeatedly triggers account lockout" class.

### Finding Description
- `process_supply` permits non-owner/non-delegate callers to add funds to any hub asset already present in `account.supply_positions` (`require_third_party_existing_supply`, contracts/controller/src/positions/supply.rs:78-97). No solvency or HF check is applied to `supply` (docs/reference/endpoints.md:55).
- `clean_bad_debt` is permissionless but only executes `execute_bad_debt_cleanup` — which seizes all remaining supply/debt positions, socializes the debt, and burns the account NFT — when remaining collateral is "at or below the dust cap" (contracts/controller/src/lib.rs:160-165; `execute_bad_debt_cleanup` at contracts/controller/src/positions/liquidation/bad_debt.rs:14-60). Only the owner-gated `force_socialize_bad_debt` omits the dust cap (scripts/permissionless_entrypoints.txt:72).
- For an account that is deeply insolvent (debt USD ≫ collateral USD), rational liquidators will not repay the debt to seize the dust collateral, so `clean_bad_debt` is the sole cleanup mechanism.
- Each cleanup attempt can be permanently defeated: the attacker watches for the account's collateral to decay to ≤ dust cap and calls `supply(attacker, victim_account_id, victim_spoke_id, [(existing_collateral_hub_asset, 1)])`. The top-up is credited to the victim's existing position at measured receipt, raising collateral above the cap, so `clean_bad_debt` reverts. Interest accrual (`update_indexes`) shrinks the real collateral again over time, but the attacker simply repeats the 1-unit top-up — the same "3 failed logins per minute" rhythm as the reference CVE.

### Impact Explanation
The victim account's bad debt is never written down: the pool's supply index is never reduced and the account, its NFT, and its debt positions persist indefinitely. Suppliers' backing shortfall is never recognized, interest keeps accruing on unrecoverable debt, and any accounting/exit flow that depends on the account being removed is frozen. This is a permanent freezing of funds / contract-unable-to-operate condition on the bad-debt path, purchasable for ~1 token unit per cleanup attempt. If the insolvent account holds more than one supply leg, the attacker must dust each leg, still a trivial cost.

### Likelihood Explanation
Requires only an unprivileged address, knowledge of the victim `account_id`/`spoke_id`, and dust amounts of an asset the account already supplies. No timing privilege is needed since `supply` is always callable while unpaused and third-party top-ups are deliberately allowed. The precondition is a real insolvent account, which is exactly the state `clean_bad_debt` exists for, so the attack surfaces whenever the mechanism is needed.

### Recommendation
Exclude third-party top-ups received after insolvency from the dust-cap measurement, or make the dust check use the collateral value at the moment the account became insolvent. Simplest fix: in `clean_bad_debt`, compute collateral excluding supply-position growth attributable to non-owner top-ups, or gate third-party `supply` top-ups on the target account's HF ≥ 1 (an insolvent account cannot accept foreign top-ups). Alternatively, allow `clean_bad_debt` to first seize-and-socialize regardless and refund dust, removing the cap's griefability.

### Proof of Concept
```rust
// Contracts: Controller deployed with a USDC/ETH market; standard test harness.
// 1. ALICE supplies USDC, borrows ETH; price crash leaves account deeply
//    insolvent with only residual USDC dust collateral.
let mut t = LendingTest::new().standard_two_asset().build();
t.supply(ALICE, "USDC", 100.0);
t.borrow(ALICE, "ETH", 3.0);
t.set_price("USDC", test_harness::usd_cents(1)); // near-total crash
assert!(!t.can_be_liquidated(ALICE)); // no liquidator will repay for dust

// 2. Collateral decays to <= dust cap; keeper calls clean_bad_debt.
let alice_id = t.resolve_account_id(ALICE);
// Attacker griefs: top up the *existing* USDC supply leg by 1 unit.
t.try_supply_to_account(ATTACKER, ALICE, "USDC", 1.0) // dust amount
    .expect("third-party top-up of existing leg is allowed");

// 3. clean_bad_debt now reverts: collateral > dust cap.
assert_contract_error(
    t.try_clean_bad_debt(KEEPER, alice_id),
    errors::COLLATERAL_ABOVE_DUST, // or the corresponding dust-cap error
);
// 4. Repeat step 2 each time accrual shrinks collateral again ->
//    bad debt is never socialized; account and NFT persist forever.
```
Supporting code: third-party top-up gate at contracts/controller/src/positions/supply.rs:78-97; cleanup entrypoint doc at contracts/controller/src/lib.rs:160-165; cleanup execution at contracts/controller/src/positions/liquidation/bad_debt.rs:14-60; dust-cap condition documented at scripts/permissionless_entrypoints.txt:72 and docs/reference/endpoints.md:63.

Caveat: I verified the dust-cap gate via documentation and entrypoint comments, but did not read the exact comparison inside `process_clean_bad_debt` (in contracts/controller/src/positions/liquidation/mod.rs); if that check already discounts post-insolvency top-ups, this analog is mitigated.