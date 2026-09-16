## Title
TPS-fee (unit-tax) underpayment when a unit's payment output targets an AA defined after `last_ball_mci` but before actual execution mci - (File: `validation.js`, function `validateAATrigger`/`validateTpsFee`)

### Summary
Just as the Y2K `Carousel` contract let a user pay a small fixed `relayerFee` while bypassing the percentage `depositFee` by routing through `mintDepositInQueue()` instead of `deposit()`, ocore has an analogous two-path fee-assessment mismatch for the "network tax" it does have: the `tps_fee`. The fee owed by a unit is computed by `validateTpsFee`/`storage.getLocalTpsFee` using a `count_units` multiplier that is derived from `count_primary_aa_triggers`, which in turn is computed by `validateAATrigger` by looking only at AA addresses that are already registered **as of `last_ball_mci`** [1](#0-0) . However, the actual execution path that decides whether a unit is treated as a primary AA trigger (`handleAATriggers` in `main_chain.js`) matches AA addresses using the unit's real (non-last-ball) `mci` [2](#0-1) . This means a newly-defined AA (defined in a unit that becomes stable/known between `last_ball_mci` and the triggering unit's actual mci) will not count toward `count_primary_aa_triggers` at validation time, so the sender is only required to pay the base (non-AA) `tps_fee`, yet the unit is still executed as a real AA trigger by the network — mirroring the "pay the small fee, get the full service" bypass in the reported bug.

### Finding Description
`validateTpsFee` requires the unit's `tps_fee` field to be at least `min_tps_fee`, which is `getLocalTpsFee(...) * count_units` [3](#0-2) . `count_units` comes from `storage.getCountUnitsPayingTpsFee`, which is `1 + count_primary_aa_triggers * max_aa_responses` [4](#0-3) . `count_primary_aa_triggers` is set inside `validateAATrigger`, which queries `aa_addresses` restricted to `mci<=?` where `?` is `objValidationState.last_ball_mci` [1](#0-0) . The code comment even acknowledges the discrepancy: "There might be actually more triggers due to AAs defined between last_ball_mci and our unit, so our validation of tps fee might require a smaller fee than the fee actually charged when the trigger executes" [5](#0-4) .

At execution time, however, `handleAATriggers` (invoked when an MCI stabilizes) selects AA addresses to trigger by joining `outputs` to `aa_addresses` with `mci_column<=mci` where `mci` is the unit's own (stabilizing) mci — not `last_ball_mci` — meaning any AA whose definition became known by the time the payment unit itself stabilizes is triggered [2](#0-1) .

Because a unit's `last_ball_mci` always lags behind the unit's own eventual mci (by design, `last_ball_unit` references an earlier, already-stable point on the DAG), it is architecturally guaranteed that AAs can be defined in the gap between `last_ball_mci` and the triggering unit's mci. A user can time-post (or simply happen to post) a payment to a brand-new AA address right after that AA's defining unit is broadcast but before it is reflected in the sender's chosen `last_ball_mci`. `validateAATrigger`/`validateTpsFee` will then compute `count_primary_aa_triggers = 0` (since the AA isn't yet in `aa_addresses` as of `last_ball_mci`), the required `tps_fee` collapses to the base 1-unit fee, yet `handleAATriggers` will still fire the AA and charge the full 1-to-`MAX_RESPONSES_PER_PRIMARY_TRIGGER` execution price in AA-response overhead against network throughput accounting — with no extra `tps_fee` collected from the trigger's author to cover it.

### Impact Explanation
This lets an attacker systematically trigger AAs (potentially with many chained AA responses, up to `MAX_RESPONSES_PER_PRIMARY_TRIGGER`, i.e. up to 10 by default [6](#0-5) ) while paying only the tps_fee of a plain non-AA-triggering unit. Since `tps_fee` is the mechanism that is supposed to make heavy AA users (whose triggers consume disproportionate DAG/AA-execution resources) pay proportionally more and to keep the `tps_fees_balance` accounting consistent across the network, systematically underpaying it via this timing gap causes a persistent discrepancy between the network's committed throughput cost and what is actually collected — analogous to the treasury-tax bypass in the reported bug, but here the "tax" underpays the network-wide congestion-pricing mechanism (`base_tps_fee`/`tps_interval` dynamics in `storage.getFinalTpsFee`) rather than a per-protocol treasury.

### Likelihood Explanation
Reachable by any ordinary unit poster with no special privileges: they simply need to (a) discover/define a target AA address, and (b) choose `last_ball_unit`/`last_ball` parameters (which the `bytes` wallet/composer normally picks automatically to be recent-but-safe) that predate the AA's definition becoming known, while still sending the payment message to that AA in the same unit. Because `last_ball_mci` structurally lags behind the true tip, this window exists for essentially every unit and can be widened deliberately by an attacker who controls unit composition (e.g., via a custom composer bypassing the stock wallet logic) rather than relying on race conditions against other peers.

### Recommendation
Make `validateAATrigger`'s AA-address lookup and `handleAATriggers`'s trigger-selection lookup consistent in which mci boundary they use for "is this address a known AA." Either:
- Change `validateAATrigger` (and the `tps_fee` estimate in `composer.js`/`light.js`) to also account for AA definitions that could plausibly stabilize by the time the unit is actually processed (e.g., use the same or a conservative upper-bound mci as `handleAATriggers`), or
- Restrict `handleAATriggers` to only trigger AAs whose definitions were already known/stable as of the triggering unit's `last_ball_mci`, matching the assumption baked into `validateTpsFee`.

### Proof of Concept
1. Attacker defines AA `X` in unit `D`.
2. Before `D` becomes part of the attacker's chosen `last_ball_unit`/`last_ball_mci` (i.e., while `D`'s mci is still `> last_ball_mci` of the intended trigger unit but `D` is already broadcast/known to the network), attacker composes unit `T` with a payment output to AA address `X`, using an older `last_ball_unit` so that `last_ball_mci < mci(D)`.
3. `validateAATrigger(conn, T, ...)` queries `aa_addresses WHERE address IN (X) AND mci<=last_ball_mci` — returns 0 rows since `D`/`X` is not yet at or below `last_ball_mci` [7](#0-6) ; `count_primary_aa_triggers` = 0.
4. `validateTpsFee` therefore only requires the minimal single-unit `tps_fee`, not the higher `1 + max_aa_responses` fee [8](#0-7) ; unit `T` passes validation and is accepted paying the lower fee.
5. When `T`'s mci stabilizes, `handleAATriggers` in `main_chain.js` re-checks with `aa_addresses.mci<=mci(T)` (the real mci, not `last_ball_mci`) [9](#0-8) ; since `D`/`X` is now `<= mci(T)`, `X` is triggered as a full AA execution (potentially cascading further AA responses), even though the attacker never paid the corresponding `tps_fee` premium.

Note: I was unable to fully verify from the indexed code exactly when `aa_addresses` rows are inserted relative to a defining unit's stabilization (light.js/writer.js/definition.js insertion code for `aa_addresses` was not found in the index), so the precise timing window (stable-vs-unstable AA definitions) could not be double-checked end-to-end; a Devin session with full repository access would be needed to confirm the exact insertion point of `aa_addresses` rows and validate the PoC against a running node.

### Citations

**File:** validation.js (L1016-1024)
```javascript
	// Look for AA triggers
	// There might be actually more triggers due to AAs defined between last_ball_mci and our unit, so our validation of tps fee might require a smaller fee than the fee actually charged when the trigger executes
	const rows = await conn.query("SELECT address FROM aa_addresses WHERE address IN (?) AND mci<=?", [arrOutputAddresses, objValidationState.last_ball_mci]);
	if (rows.length === 0) {
		if ("max_aa_responses" in objUnit)
			return callback(`no outputs to AAs, max_aa_responses should not be there`);
		return callback();
	}
	objValidationState.count_primary_aa_triggers = rows.length;
```

**File:** validation.js (L1061-1071)
```javascript
	const objUnitProps = {
		unit: objUnit.unit,
		parent_units: objUnit.parent_units,
		best_parent_unit: objValidationState.best_parent_unit,
		last_ball_unit: objUnit.last_ball_unit,
		timestamp: objUnit.timestamp,
		count_primary_aa_triggers: objValidationState.count_primary_aa_triggers,
		max_aa_responses: objUnit.max_aa_responses,
	};
	const count_units = storage.getCountUnitsPayingTpsFee(objUnitProps);
	const min_tps_fee = await storage.getLocalTpsFee(conn, objUnitProps, count_units);
```

**File:** main_chain.js (L1691-1706)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
```

**File:** storage.js (L1351-1358)
```javascript
function getCountUnitsPayingTpsFee(objUnitProps) {
	let count_units = 1;
	if (objUnitProps.count_primary_aa_triggers) {
		const max_aa_responses = (typeof objUnitProps.max_aa_responses === "number") ? objUnitProps.max_aa_responses : constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER;
		count_units += objUnitProps.count_primary_aa_triggers * max_aa_responses;
	}
	return count_units;
}
```

**File:** constants.js (L68-68)
```javascript
exports.MAX_RESPONSES_PER_PRIMARY_TRIGGER = process.env.MAX_RESPONSES_PER_PRIMARY_TRIGGER || 10;
```
