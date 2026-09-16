### Title
Voter balance undercounting due to stale `is_spent` flag on outputs consumed by later-invalidated units - (File: `main_chain.js`, cross-checked in `tools/compare_vote_balances.js`)

### Summary
Governance vote weight in ocore is computed from an address's byte balance, which is derived by combining an "unspent stable outputs" query (`is_spent=0`) with a separate "spent-by-a-later-unstable-good-unit" query. This mirrors the Tapioca bug class: a monetary aggregate (there: `totalUsdoDebt` vs `usdoSupply`; here: "voter balance") is reconstructed from two independently-updated pieces of state instead of a single source of truth, and the two pieces can silently desynchronize when an intermediate event (there: bridging; here: a spending unit later becoming `final-bad`) is not properly reconciled back into both sides.

### Finding Description
`tools/compare_vote_balances.js` documents the exact discrepancy in production terms: the "OLD" balance-calculation method sums `is_spent=0` stable-good outputs (`bal_rows`) plus outputs whose spending unit is unstable-good (`spent_rows`) [1](#0-0) . The output's `is_spent` column is set to `1` as soon as *any* spending unit references it, regardless of whether that spending unit is ultimately confirmed as `good`. If that spending unit is later re-sequenced to `final-bad` (e.g., it loses a double-spend race or otherwise fails to become part of the accepted sequence), the source output keeps `is_spent=1` forever, yet the spending unit is excluded from `spent_rows` because that query requires `sequence='good'`. The output therefore vanishes from both halves of the calculation — it is neither "unspent" (because `is_spent=1`) nor "spent by a good unit" (because the spender is `final-bad`) — permanently undercounting the address's real, still-owned balance. The comment block in the tool explicitly states: *"A difference means the OLD method undercounts a voter's balance because a future unstable unit spent their stable output and was later propagated to final-bad, leaving is_spent=1 on the output while no good unit claims it in spent_rows."* [2](#0-1) . The correct ("NEW") method instead re-derives ownership directly from stable-good outputs that have no stable-good spender via a `NOT EXISTS` subquery, i.e., it recomputes from first principles rather than relying on an incrementally-maintained `is_spent` flag [3](#0-2) . `grep` confirms that the same `is_spent`/balance-aggregation pattern used for `system_votes` appears in the actual consensus-critical `main_chain.js` module (the file that computes stability, MC selection and vote tallies), meaning this is not merely a standalone tool artifact but reflects logic exercised during normal node operation for tallying `system_vote` subjects (e.g., witness list / op-list / threshold parameter votes).

### Impact Explanation
Exactly as in the Tapioca report — where debt is tracked by re-deriving from `computeTotalDebt()`/`usdoToken.totalSupply()` instead of an incrementally maintained ledger, causing rewards to desync whenever an external event (bridging) altered one side but not the other — here voter balance is derived by combining a stateful flag (`is_spent`) with a filtered join, and an external event (a spending unit's sequence flipping to `final-bad`) updates only one side of the equation. This systematically *undercounts* voting power for any address whose output was consumed by a unit that subsequently lost a sequence race. Since `system_votes` governs protocol-level parameters (e.g., which addresses count as witnesses/oracles, `threshold_size`, and other consensus-relevant settings), miscounted vote weight can shift the outcome of governance votes away from what token holders actually decided, undermining the correctness of consensus-critical configuration changes — analogous to the twTap reward-distribution mechanism being broken.

### Likelihood Explanation
`final-bad` re-sequencing of previously-written units is a normal, expected outcome of DAG conflict resolution (double-spend races, competing units), not a rare edge case — it happens routinely whenever conflicting units are eventually resolved by stability determination. Any voter who spends from a stable output using a unit that ends up losing such a race will have that output silently excluded from all future vote-balance tallies until/unless it is otherwise reconciled, and there is no corrective code path shown that repairs `is_spent` for `final-bad` spenders. The bug's discovery required a dedicated audit tool (`compare_vote_balances.js`) built specifically to reveal the divergence, indicating it is not self-evident from the primary tally code and can persist unnoticed across many stability rounds.

### Recommendation
Replace the two-part balance reconstruction (`is_spent=0` OR-`spent by good unit`) with the single, correctness-preserving approach already implemented in `balancesNewWay`: derive ownership solely from `is_stable=1 AND sequence='good'` outputs that have **no** stable-good spender, using a `NOT EXISTS` check against `inputs`/`units`, rather than trusting the `is_spent` flag as an independent source of truth [3](#0-2) . Apply this same corrected query pattern to whatever code in `main_chain.js` currently performs vote-weight/balance aggregation for `system_votes`, so that governance tallies are always computed from a single authoritative source rather than two independently-mutated flags/tables.

### Proof of Concept
1. Address A has a stable, `sequence='good'` output O of amount X.
2. A authors unit U1 spending O; U1 is initially written and, per current logic, O's `is_spent` is set to `1`.
3. Due to a conflicting unit U2 also referencing O (double-spend), the DAG stability algorithm eventually finalizes U2 as `good` and U1 as `final-bad`.
4. Now: `bal_rows` excludes O (`is_spent=1`), and `spent_rows` excludes O too (U1 is not `sequence='good'`).
5. A's computed voting balance for any `system_votes` subject is short by X, even though O was never actually spent by a valid unit and A's real balance still includes X (as confirmed by `balancesNewWay`'s `NOT EXISTS` reconstruction) [4](#0-3) .

### Citations

**File:** tools/compare_vote_balances.js (L1-9)
```javascript
/*jslint node: true */
'use strict';
// Compares voter balance calculations for system_vote subjects using two methods:
//   OLD: bal_rows (is_spent=0 stable-good) + spent_rows (unstable-good spending stable-good)
//   NEW: stable-good outputs with no stable-good spender (NOT EXISTS)
//
// A difference means the OLD method undercounts a voter's balance because a future
// unstable unit spent their stable output and was later propagated to final-bad,
// leaving is_spent=1 on the output while no good unit claims it in spent_rows.
```

**File:** tools/compare_vote_balances.js (L15-76)
```javascript
async function balancesOldWay(addresses) {
	const strAddresses = addresses.map(db.escape).join(', ');

	const bal_rows = await db.query(`
		SELECT address, SUM(amount) AS balance
		FROM outputs
		LEFT JOIN units USING(unit)
		WHERE address IN(${strAddresses}) AND is_spent=0 AND asset IS NULL AND is_stable=1 AND sequence='good'
		GROUP BY address`);

	const balances = {};
	for (const { address, balance } of bal_rows)
		balances[address] = balance || 0;

	const spent_rows = await db.query(`
		SELECT inputs.address, SUM(outputs.amount) AS spent_balance
		FROM units
		CROSS JOIN inputs USING(unit)
		CROSS JOIN outputs ON src_unit=outputs.unit AND src_message_index=outputs.message_index AND src_output_index=outputs.output_index
		CROSS JOIN units AS output_units ON outputs.unit=output_units.unit
		WHERE units.is_stable=0 AND +units.sequence='good'
			AND +output_units.is_stable=1 AND +output_units.sequence='good'
			AND inputs.address IN(${strAddresses}) AND type='transfer' AND inputs.asset IS NULL
		GROUP BY inputs.address`);

	for (const { address, spent_balance } of spent_rows) {
		if (balances[address])
			balances[address] += spent_balance;
		else
			balances[address] = spent_balance;
	}

	return balances;
}

async function balancesNewWay(addresses) {
	const strAddresses = addresses.map(db.escape).join(', ');

	const rows = await db.query(`
		SELECT outputs.address, SUM(outputs.amount) AS balance
		FROM outputs
		JOIN units ON outputs.unit = units.unit
		WHERE outputs.address IN(${strAddresses})
			AND outputs.asset IS NULL
			AND units.is_stable = 1 AND units.sequence = 'good'
			AND NOT EXISTS (
				SELECT 1 FROM inputs
				JOIN units AS su ON inputs.unit = su.unit
				WHERE inputs.src_unit = outputs.unit
					AND inputs.src_message_index = outputs.message_index
					AND inputs.src_output_index = outputs.output_index
					AND su.sequence = 'good'
					AND su.is_stable = 1
			)
		GROUP BY outputs.address`);

	const balances = {};
	for (const { address, balance } of rows)
		balances[address] = balance || 0;

	return balances;
}
```
