### Title
An insolvent borrower can straddle `BAD_DEBT_USD_THRESHOLD` to block the permissionless `clean_bad_debt` queue for the shared market book - (File: contracts/controller/src/positions/liquidation/curve.rs)

### Summary
The Discourse report describes a single malicious tenant stalling a shared defer queue for all co-tenants. The analog here is the permissionless bad-debt cleanup gate: `is_socializable_bad_debt` only admits an account when `total_debt > total_collateral` *and* `total_collateral <= BAD_DEBT_USD_THRESHOLD` (curve.rs:25-27). An attacker who holds an insolvent account can keep posting just enough collateral (straddling one WAD unit above the cap) to shut that gate while remaining deeply insolvent. Every subsequent `clean_bad_debt` call against the account fails the gate, so the shared market book retains the bad debt until the governed `force_socialize_bad_debt` path is driven through timelock — a delay the attacker controls for the cost of roughly `BAD_DEBT_USD_THRESHOLD` dollars of collateral.

### Finding Description
- `curve.rs:25-27` — the gate is value-based and monotonic: `total_collateral <= BAD_DEBT_USD_THRESHOLD` is required. Any collateral above the cap, however small the margin, rejects cleanup.
- `bad_debt.rs:14-60` — `execute_bad_debt_cleanup` is what clears the account: it seizes all remaining supply/debt positions via `pool_seize_positions_call`, releases spoke usage, burns the NFT, and emits `CleanBadDebtEvent`. If the gate rejects, none of this runs; debt and its accrued interest stay on the shared `(hub, asset)` book.
- Reachability: the attacker owns the account. After becoming insolvent (borrow + price move, or self-inflicted via `multiply`), they call `supply` to top up one of their existing collateral positions to `BAD_DEBT_USD_THRESHOLD + ε`. The certora boundary rule `bad_debt_straddle_blocks_dust_gate` (certora/controller/spec/boundary_rules.rs:50-67) formalizes exactly this: `collateral_wad >= BAD_DEBT_USD_THRESHOLD + 1` with `debt_wad > collateral_wad` shuts the gate while insolvent.
- Because it is a straddle, the attacker can also flip back: a partial `withdraw` of the straddle collateral is impossible while HF < 1, so the block persists until governance intervenes — mirroring the defer queue being stalled for other tenants.

### Impact Explanation
Bad debt accrues interest on the shared pool book rather than being socialized promptly. Suppliers of that market carry the growing index write-down exposure, and per the threat model, a supplier who exits before eventual cleanup avoids the loss — so the delay transfers loss from early exiters to later/remaining suppliers. The permissionless cleanup lane (the "queue") is denied to all callers for as long as the attacker maintains the straddle; only the delayed, privileged `force_socialize_bad_debt` runbook recovers. This is temporary freezing/delayed loss allocation of protocol funds, matching Medium severity.

### Likelihood Explanation
The attacker needs an insolvent account and ~`BAD_DEBT_USD_THRESHOLD` of postable collateral — modest capital. No privileged role, oracle manipulation, or external dependency is required; `supply` top-ups to an existing position are permissionless (Elevation.5 in the threat model confirms top-ups only require existing positions). The only mitigation is the governed force path, which introduces timelock delay by design. The gate arithmetic is directly evidenced in production code and the formal spec.

### Recommendation
Bound the straddle: e.g., admit cleanup when `total_debt - total_collateral` (the shortfall) is below the dust cap rather than gating on raw collateral, or let `clean_bad_debt` succeed whenever the account is insolvent and either below the cap *or* has been continuously insolvent for a configured ledger window. Alternatively, make `clean_bad_debt` permissionless for any insolvent account whose collateral seizure cannot cover debt, since `pool_seize_positions_call` already handles arbitrary residual positions.

### Proof of Concept
1. Attacker creates an account, supplies collateral, borrows near max LTV.
2. Price drift (or a `multiply` loop) pushes HF < 1 and then `total_debt > total_collateral`.
3. Attacker calls `supply(caller=attacker, account_id, spoke_id, assets=[...])` topping up collateral to `BAD_DEBT_USD_THRESHOLD + 1` USD.
4. Any keeper/user calls `clean_bad_debt(account_id)`: `is_socializable_bad_debt` returns false (debt > collateral but collateral > cap) → reverts.
5. Repeat: debt keeps accruing; the book's bad debt is only clearable via `force_socialize_bad_debt` (owner-gated, `BadDebtGate::InsolventOnly`), i.e., behind governance delay. Attacker maintains the straddle indefinitely at fixed cost.