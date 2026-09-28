### Title
Any user can permanently grief `clean_bad_debt` on an insolvent account by topping up its existing supply positions to keep collateral above the dust threshold - (File: contracts/controller/src/positions/liquidation/mod.rs)

### Summary
The permissionless `clean_bad_debt` entrypoint reverts with `CannotCleanBadDebt` unless the account's remaining collateral is at or below the fixed `BAD_DEBT_USD_THRESHOLD` (5 USD). At the same time, `supply` lets any third party add funds to a foreign account as long as the account already holds a supply position in that hub asset. An insolvent account by definition still holds supply positions (that is its collateral), so anyone can donate a small amount above $5 to any of its existing collateral legs and make every `clean_bad_debt` call on that account revert — the exact analog of the CrabNetting nonce grief: one user's reachable state change forces a protocol-critical batch/cleanup call to always revert.

### Finding Description
- `process_supply` loads a foreign `account_id` and only restricts third parties to hub assets already in `account.supply_positions` (`require_third_party_existing_supply`), so topping up an existing collateral leg requires no owner or delegate authority — `contracts/controller/src/positions/supply.rs:78-97`.
- `process_clean_bad_debt` is permissionless and routes into `socialize_bad_debt` with `BadDebtGate::DustCapped` — `contracts/controller/src/positions/liquidation/mod.rs:196-243`.
- `socialize_bad_debt` computes account risk totals from live state and asserts `is_socializable_bad_debt(total_debt, total_collateral)`, i.e. debt must exceed collateral **and** collateral must be ≤ `BAD_DEBT_USD_THRESHOLD`; otherwise it reverts with `CannotCleanBadDebt` — `mod.rs:212-235`, `contracts/controller/src/constants.rs` (threshold constant), `contracts/controller/src/positions/liquidation/curve.rs` (`is_socializable_bad_debt`).
- The griefer (or the insolvent borrower themselves) calls `supply(caller, victim_account_id, victim_spoke, [(existing_collateral_key, dust_amount)])`. Because only a `caller.require_auth` and an existing supply position are needed, a donation that lifts `total_collateral` above $5 makes `clean_bad_debt` revert on every subsequent call. The griefer can repeat this indefinitely; each grief costs at most the dust margin above $5.
- The same effect blocks the automatic post-liquidation cleanup in `check_bad_debt_after_liquidation` (`mod.rs:135`), so a bad-debt account can be kept alive across liquidations too.

### Impact Explanation
`clean_bad_debt` is the permissionless mechanism that socializes dust-collateral insolvent accounts by writing debt down through the supply index and deleting the account. Blocking it leaves bad debt permanently on the books, keeps zombie accounts and their NFT alive, and delays/forces socialization through the owner-only `force_socialize_bad_debt` governance path — a temporary-to-permanent freeze of a protocol-critical function reachable by any unprivileged address. Matches the reported class: a queued/batch protocol operation that always reverts because of a user-controlled state flag.

### Likelihood Explanation
- Fully permissionless: `supply` accepts any authenticated caller for existing supply legs (`supply.rs:86-95`), and `clean_bad_debt` accepts any authenticated caller (`mod.rs:196-199`).
- Cost is bounded by the $5 threshold — the attacker donates just enough to push `total_collateral` above it, which is cheap, and the insolvent borrower has a direct incentive to do this to prevent socialization of their own debt.
- The collateral price feeds required to pass the gate are already required for cleanup, so no additional precondition is needed.

### Recommendation
- Forbid third-party `supply` into accounts that are insolvent (HF < 1 or `total_debt > total_collateral`), mirroring the "third parties may only top up existing positions" restriction with an insolvency check; or
- Compute the dust threshold against the collateral that existed before the last user action, or treat third-party top-ups into insolvent accounts as immediate revenue/seizable donations; or
- Make the dust gate evaluate only positions that predate the insolvency, or allow `clean_bad_debt` to first confiscate donated supply as protocol revenue so the donation cannot raise the gate.

### Proof of Concept
1. Alice's account has debt with residual collateral of $4 (< `BAD_DEBT_USD_THRESHOLD`), so `clean_bad_debt(caller, alice_id)` would succeed.
2. Griefer (or Alice) calls `supply(griefer, alice_id, alice_spoke, [(collateral_key, 2 USD worth)])`. `require_third_party_existing_supply` passes because `collateral_key` is already in `account.supply_positions`; `process_deposit` credits it via `pool_supply_call`.
3. `total_collateral` is now ~$6 > $5.
4. Any subsequent `clean_bad_debt(caller, alice_id)` reaches `socialize_bad_debt`, where `is_socializable_bad_debt` returns false and the call reverts with `CannotCleanBadDebt` (`mod.rs:229-235`). The griefer can re-dust after each liquidation pass, since `check_bad_debt_after_liquidation` shares the same gate, keeping the bad-debt account uncleanable through the permissionless path indefinitely.