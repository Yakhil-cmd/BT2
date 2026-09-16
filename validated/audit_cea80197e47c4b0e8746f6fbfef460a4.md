### Title
Race window between AA-trigger precheck (`last_ball_mci` snapshot) and actual trigger execution (current `mci`) allows unvalidated/underpaid AA triggers - ([File: validation.js])

### Summary
`validateAATrigger()` (analogous to PX4's `mission_feasibility_checker`/`geofence` precheck) decides how many primary AA triggers a unit will produce, and therefore how much `tps_fee` must be paid and whether the "at most one primary AA trigger" / "at most one output per asset to that AA" rules are satisfied. This decision is made using a *stale* snapshot — the set of AA addresses known as of `objValidationState.last_ball_mci` — while the *actual* trigger execution, performed later in `main_chain.js` when the unit's own MCI stabilizes, uses the AA-address set known as of the unit's own (later) `main_chain_index`. Because new AAs can become known between `last_ball_mci` and the unit's real `mci` (a normal, attacker-influenceable occurrence in an async DAG), the precheck and the real execution can disagree about how many/which AAs are triggered by the same posted unit.

### Finding Description
`validateAATrigger()` explicitly acknowledges this discrepancy in a comment: [1](#0-0) 

It queries AA addresses only up to `last_ball_mci`: [2](#0-1) 

and enforces the "single primary trigger" / "single output per asset" invariants purely against that stale count: [3](#0-2) 

The `tps_fee` that is actually required to be paid is derived from this same stale `count_primary_aa_triggers` in `validateTpsFee()`: [4](#0-3) 

However, when the unit actually stabilizes and its AA triggers are executed, `handleAATriggers()` in `main_chain.js` looks up AA addresses using the unit's own (current, later) `main_chain_index`, not the `last_ball_mci` used during validation: [5](#0-4) 

Because a new AA can be defined and become known (stable) between the posting unit's `last_ball_mci` and its own eventual `main_chain_index`, an output address that was *not* an AA at validation time can become an AA by the time the trigger actually executes. This means:
- A unit that was validated as having 0 or 1 primary AA triggers can end up actually invoking a different/additional AA at execution time, one that never went through the "more than 1 primary AA trigger" rejection in `validateAATrigger()` (`validation.js:1025-1030`).
- The `tps_fee` charged (computed off the stale trigger count) can under-pay for the AA response capacity actually consumed (`storage.getCountUnitsPayingTpsFee`, `validation.js:1067-1070`), since it was calculated against a smaller `count_primary_aa_triggers` than reality.
- Because different nodes can have different local views of exactly when a given AA address became "known" relative to a still-unstable unit (races in stabilization order across nodes with different unstable DAG contents), nodes can disagree about whether the trigger rules were respected, which is exactly the "node disagreement on validity/stability" failure mode called out in the validation rules for this analog.

This is structurally the same bug class as CVE-2024-24255: a safety precheck (mission feasibility/geofence check) is evaluated against one snapshot of state, but the actual action (mission execution / AA trigger execution) is carried out against a later, potentially different state, and the two are not re-synchronized or re-validated at execution time.

### Impact Explanation
An attacker (any unposted unit poster / AA trigger sender) can craft a unit sending outputs to an address that is *not yet* a known AA at `last_ball_mci` but becomes one before the unit's own MCI is finally computed. This unit passes `validateAATrigger()`/`validateTpsFee()` as an ordinary payment (or as a legitimately-priced 1-trigger unit), but at execution time is treated as a primary AA trigger to a different/additional AA, bypassing:
- The `tps_fee` sizing that the network relies on for congestion pricing (fee-evasion / network resource starvation for triggered AA execution capacity), and
- The "at most one primary trigger, at most one output per asset to that AA" invariant meant to bound the AA's response processing per unit.

This can cause AA fund-handling logic to run in configurations its own guards assumed impossible (multiple/uncontrolled triggers reaching an AA without going through the intended trigger-count validation), and can create scenarios where nodes disagree on whether a given historical unit correctly satisfied AA-trigger validation rules, since the "AA known as of X" set is a function of each node's asynchronous stabilization progress.

### Likelihood Explanation
The precondition (a new AA becoming known between a unit's declared `last_ball_mci` and its own eventual stabilization MCI) is a routine occurrence in the DAG, not an exotic edge case — it happens whenever an AA is defined concurrently with other units being posted, which is expected on a live network. No privileged access is required; only a normal unit author or AA trigger sender is needed. The main obstacle is precise timing to land the output-sending unit's stabilization in the narrow window after the target AA becomes known but reusing a `last_ball_mci` before it — feasible for an attacker who controls unit timing/parents, but requiring some care, matching the "AC:H" (high attack complexity) rating of the analogous CVE.

### Recommendation
Re-validate the AA-trigger/tps-fee invariants (single trigger, single output-per-asset, sufficient `tps_fee`) using the same AA-address snapshot that will actually be used at execution time (i.e., re-check against the unit's own eventual `main_chain_index`/AA-address set at trigger-execution time in `main_chain.js:handleAATriggers`), and reject/bounce triggers whose realized trigger count or target AA set differs from what was validated in `validateAATrigger()`/`validateTpsFee()`, rather than only logging the discrepancy in a comment.

### Proof of Concept
1. Author unit `U` with a payment output to address `X`, where `X` is not yet listed in `aa_addresses` as of `U`'s `last_ball_mci` (so `validateAATrigger()` treats `U` as a non-AA-triggering, normally priced payment — `validation.js:1018-1022`).
2. Concurrently, cause an AA definition for `X` to become stable with an effective `mci` that is `<= U`'s eventual `main_chain_index` but `> U`'s `last_ball_mci` (achievable by controlling parent selection/timing of the AA-defining unit relative to `U`).
3. Let `U` stabilize. `handleAATriggers()` in `main_chain.js:1691-1706` will now find `X` as a matching AA for `U`'s output (query uses `U`'s actual `main_chain_index`, not the `last_ball_mci` used in step 1) and execute a primary AA trigger that was never subjected to the `validateAATrigger()`/`validateTpsFee()` checks that assumed `U` had zero (or fewer) triggers.
4. Because indexing/exact interplay between `pemCurvesFixMci`-gated rules and the AA-known-mci column (`aa_addresses.mci` vs `aa_definition_units.main_chain_index`, `main_chain.js:1694`) could not be fully traced end-to-end within the scope of this review, the precise minimal reproduction sequence (exact MCI deltas required) is not fully verified here and would need to be validated against a live/test network to confirm the exact conditions and quantify the resulting fee/trigger-count mismatch.

### Citations

**File:** validation.js (L1012-1037)
```javascript
	const arrOutputAddresses = Object.keys(outputCounts);
	if (arrOutputAddresses.length === 0)
		return callback("no output addresses found in payment messages");

	// Look for AA triggers
	// There might be actually more triggers due to AAs defined between last_ball_mci and our unit, so our validation of tps fee might require a smaller fee than the fee actually charged when the trigger executes
	const rows = await conn.query("SELECT address FROM aa_addresses WHERE address IN (?) AND mci<=?", [arrOutputAddresses, objValidationState.last_ball_mci]);
	if (rows.length === 0) {
		if ("max_aa_responses" in objUnit)
			return callback(`no outputs to AAs, max_aa_responses should not be there`);
		return callback();
	}
	objValidationState.count_primary_aa_triggers = rows.length;
	if (objValidationState.count_primary_aa_triggers > 1) {
		if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci)
			return callback(`more than 1 primary AA trigger (${objValidationState.count_primary_aa_triggers})`);
		if (storage.getMinRetrievableMci() > constants.pemCurvesFixMci)
			return callback(createTransientError(`more than 1 primary AA trigger (${objValidationState.count_primary_aa_triggers})`));
	}
	if ((objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) && objValidationState.count_primary_aa_triggers === 1) {
		const address = rows[0].address;
		for (let asset in outputCounts[address]) {
			if (outputCounts[address][asset] > 1)
				return callback(`more than 1 output to the same AA ${address} for asset ${asset}`);
		}
	}
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
