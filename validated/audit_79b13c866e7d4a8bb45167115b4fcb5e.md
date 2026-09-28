### Title
Gifted collateral inflates `total_collateral` past the dust gate, permanently disabling permissionless `clean_bad_debt` - (File: contracts/controller/src/positions/liquidation/mod.rs)

### Summary
Analog of CVE-2024-57883: there, `huge_pmd_unshare` uses a folio refcount as the "is this page table shared" test, but unrelated callers (`split_huge_pages`, damon, page_idle) can inflate that refcount, so the unmap is skipped and both the page table and the pages it maps leak. Here, `socialize_bad_debt` uses the account's aggregate `total_collateral` (computed over all of its supply positions) as the "residual dust" test, but any unprivileged third party can inflate that aggregate by supplying collateral into the victim's account (`supply` credits `account_id`, not the caller). The `BadDebtGate::DustCapped` check then reports the account as above the $5 threshold, the permissionless cleanup is skipped, and the bad debt — the analog of the leaked page table plus its never-freed HugeTLB pages — persists and keeps accruing against suppliers.

### Finding Description
`process_clean_bad_debt` / `socialize_bad_debt` admit an account only when `is_socializable_bad_debt(total_debt, total_collateral)` holds: ceiled risk debt must exceed half-up unweighted collateral, and collateral must be at or below `BAD_DEBT_USD_THRESHOLD` ($5). `total_collateral` is the sum over `account.supply_positions` — a value the account owner does not control. `supply(caller, account_id, spoke_id, assets)` with a nonzero `account_id` mints shares into that existing account under the caller's payment, with no owner opt-in (this is the standard on-behalf-of supply shape exercised in tests as `try_supply_to_account(BOB, ALICE, ...)`). A $6 collateral donation to an account carrying e.g. $100 of unpayable debt moves `total_collateral` from $0–5 to $6 while `total_debt > total_collateral` still holds, so the account stays insolvent but the dust gate is now closed forever — the donation cannot be withdrawn by the donor and the victim cannot be relied on to remove it (a dead/abandoned account, or one whose NFT owner is unresolvable, can never shed it). [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
The cleanup path is the protocol's only bad-debt socialization primitive besides the owner-only `force_socialize_bad_debt` governance runbook. With the permissionless path blocked, bad debt remains live and its borrow index keeps compounding against the market's supply index, while no write-down can be applied. This matters most exactly where liquidation is already unreachable: the documented "narrow band" where every liquidation offer reverts (whole-unit sub-3-decimal legs, invariants.md:434–437), accounts whose collateral leg carries `no_seize` (cleanup bypasses listing flags; liquidation does not), or positions priced outside the sanity band. A supplier can also exploit the ordering deliberately: donate $6 of collateral to freeze the cleanup gate, withdraw their own supply at the un-impaired index, and leave the eventual owner-forced socialization loss concentrated on the remaining suppliers — theft of user funds through induced loss concentration, plus protocol-level bad debt accrual during the forced-cleanup delay, which the runbook itself notes may never complete ("an insolvent account may require the governed force-socialize runbook"). The donations are small and bounded (~$5 per victim account) while the deferred write-down can be arbitrarily larger. [4](#0-3) [5](#0-4) 

### Likelihood Explanation
Requires only that an insolvent account exist with residual collateral at or below $5 — the exact state the permissionless path was built for — plus a third-party `supply` call with `account_id = victim`, `spoke_id = victim spoke`, and `assets` containing any listed collateral asset worth >$5. No governance action, no oracle manipulation, no flash loan, no privileged role. The donor's capital is sacrificed, so the attack is rational only when (a) the donor is a supplier escaping a larger write-down, (b) the donor is a supplier in the same market front-running before exiting, or (c) pure griefing of a market where socialization would hurt a counterparty. Cost is fixed and tiny; conditions recur naturally.

### Recommendation
Decouple the dust gate from attacker-inflatable state, mirroring the upstream fix's "independent shared count": measure the permissionless threshold against the collateral the account cannot have been gifted — e.g., gate on collateral value at first insolvency observation, or store a `bad_debt_candidate` marker with a snapshot of collateral when the gate first opens. Alternatively, allow permissionless cleanup when `total_debt > total_collateral` regardless of the dust cap but bound the loss socialized, or treat gifted supply below a per-leg threshold as not counting toward the dust gate. At minimum, add a permissionless fallback: if an account was once below the threshold and a donation pushes it above, the cleanup should still proceed — the donation is already forfeited to revenue on cleanup anyway.

### Proof of Concept
1. Alice's account: $0 collateral, $100 debt in market M (or collateral $3 ≤ $5, debt $100). `clean_bad_debt(any_caller, alice_id)` currently succeeds.
2. Attacker calls `supply(caller=attacker, account_id=alice_id, spoke_id=alice_spoke, assets=[(hub, collateral_asset, $6)])`. Shares are minted to Alice's account; attacker cannot retrieve them.
3. `clean_bad_debt(any_caller, alice_id)` now reverts with `CannotCleanBadDebt` (114): `is_socializable_bad_debt` sees `total_collateral = $6 > $5`.
4. The debt keeps compounding. Liquidation is unreachable if the account is in the whole-unit revert band or its collateral leg is `no_seize`. Only the timelocked owner path `force_socialize_bad_debt` remains — a privileged recovery for what should be a permissionless operation.
5. Optional profit leg: before step 2, attacker is a large supplier in M; after blocking cleanup, attacker calls `withdraw` to exit at the current supply index; when forced cleanup eventually runs, the index write-down falls on the remaining suppliers.

### Citations

**File:** contracts/controller/src/positions/liquidation/mod.rs (L229-235)
```rust
    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);
```

**File:** docs/reference/invariants.md (L424-437)
```markdown
repayment refunded, and a plan left with no seizure reverts. Such a leg is the
account's only supply position, so the seizure stays proportional. On a
solvent account whose leg holds a whole unit, the partial quote can change.
When one unit's value divided by `1 + bonus` covers the whole debt plus one base
unit of each debt leg, the quote becomes the whole debt and the leg rounds up to
one unit. That full close can pay the liquidator more than the quoted bonus.
Otherwise, when the quote seizes less than one unit plus a `1e-6` margin, it
rises to the repayment that backs one unit plus the margin, if that repayment
is below the whole debt. The seizure then refunds the margin, rounded down to
whole debt-token units. Thus such an account stays liquidatable below `HF = 1`, by a one-unit
sale or by a full close. The exception is a debt in the narrow band where
neither change applies: if the curve quote backs less than one unit, every
offer reverts until accrual or a price move ends that state. See
[whole-unit legs](formulas.md#bonus-and-target-repayment).
```

**File:** docs/reference/invariants.md (L463-469)
```markdown
### INV-LIQ-04 — Bad-debt socialization is explicit and total

Permissionless cleanup requires ceil risk debt greater than half-up unweighted
collateral and collateral at or below the fixed $5 dust threshold. Owner-only
forced cleanup omits the dust cap. Both require debt, readable account and NFT
state, valid required prices and no active flash guard. Listing flags and
global pause do not block standalone cleanup.
```

**File:** docs/explanation/threat-model.md (L310-315)
```markdown
The compile-time dust cleanup threshold and governance-settable collateral
floor can diverge. Above the permissionless cleanup threshold, an insolvent
account may require the governed [force-socialize runbook](../reference/runbooks/force-socialize-bad-debt.md).
An account whose ceil risk debt does not exceed half-up unweighted collateral
is ineligible, even if its health factor is below one and listing flags block
liquidation.
```

**File:** docs/reference/runbooks/force-socialize-bad-debt.md (L31-34)
```markdown
   simulate `force_socialize_bad_debt`. If collateral is at or below $5 and
   `D > C` holds, use permissionless `clean_bad_debt` instead; it needs no
   governance.
3. Check every position's price status. Missing or invalid required prices
```
