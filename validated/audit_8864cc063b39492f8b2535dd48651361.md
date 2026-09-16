## Title
Undercounted `count_primary_aa_triggers` allows TPS fee underpayment — ([File: validation.js])

## Summary
The reported bug class is a counter (`investorCount`) that isn't incremented for certain code paths that should count toward it, letting an actor bypass logic gated on that counter. The closest reachable analog in `ocore` is `objValidationState.count_primary_aa_triggers`, computed in `validateAATrigger()` in [1](#0-0) , which is then used to determine `count_units` for TPS-fee sufficiency checks in `validateTpsFee()` [2](#0-1) . Any unprivileged unit poster controls the outputs of their own unit, so they control this counter's inputs directly.

## Finding Description
`validateAATrigger` counts primary AA triggers strictly from `SELECT address FROM aa_addresses WHERE address IN (?) AND mci<=?` against `arrOutputAddresses`, i.e., addresses that appear in `payment` message outputs of the unit [3](#0-2) . This count is stored in `objValidationState.count_primary_aa_triggers` and later fed into `storage.getCountUnitsPayingTpsFee()`: [4](#0-3) 

which multiplies `count_primary_aa_triggers * max_aa_responses` to derive `count_units`, the divisor/multiplier used to compute the TPS fee owed for the unit (`getLocalTpsFee`, `validateTpsFee`) [5](#0-4) [6](#0-5) .

The actual downstream execution path that spends node compute/bandwidth resources — `handleAATriggers()` in `main_chain.js` — determines real AA triggers with a *different* query, using a stricter condition that also excludes units whose author is itself an AA address: [7](#0-6) 

Specifically, the actual-trigger query filters `AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit)` and requires `outputs.asset IS NULL OR is_private=0`, and gates the mci comparison on `mci_column` (`aa_addresses.mci` vs `aa_definition_units.main_chain_index`, switched by `constants.pemCurvesFixMci`) [8](#0-7) . `validateAATrigger`'s counting query has no such author-exclusion and uses only `aa_addresses.mci<=last_ball_mci` [9](#0-8) .

Because the counting logic that gates the TPS-fee charge (`validateAATrigger`) is not kept structurally identical to the logic that actually triggers AA execution (`handleAATriggers`), a poster can craft units whose outputs satisfy the "counted as a trigger" condition in one path but not the other, or vice versa — analogous to the reported bug where `preallocate()` and the regular purchase path used two different, non-synchronized conditions to decide whether to bump `investorCount`. Here the mismatch is between the validation-time fee-charging path and the stabilization-time trigger-firing path.

## Impact Explanation
If a poster can construct a unit where the validation-time counting path (`validateAATrigger`) undercounts triggers relative to what `handleAATriggers` will actually fire and process (extra state execution, extra response units, extra AA-side balance/storage load), the poster pays TPS fee for fewer "trigger units" than actually execute. This under-priced use of node/AA execution resources is a fee-evasion / resource-drain vector on the TPS-fee economic model that underlies network throughput fairness — a medium-severity issue relative to correctness of the fee mechanism, not a full loss of funds.

## Likelihood Explanation
Reaching this path only requires posting an ordinary unit with a `payment` output to an AA address — something any unprivileged poster can already do. The divergence is subtle (author-exclusion and mci-column differences) and may not be trivially exploitable without deeper reproduction (e.g., is it actually possible in practice for a poster's own unit to be authored by an address that is simultaneously an `aa_addresses` entry, given AAs cannot author units directly through normal unit posting?). I could not confirm within the exploration performed that the specific divergence produces an actually exploitable fee-undercount in a currently reachable scenario — this requires deeper trace-through of `aa_addresses` population and whether the `NOT EXISTS (unit_authors JOIN aa_addresses)` branch is ever reachable for a unit that also legitimately counts as a primary trigger for `count_primary_aa_triggers` purposes.

## Recommendation
Unify the trigger-counting predicate used in `validateAATrigger` (validation-time fee gating) with the predicate used in `handleAATriggers` (execution-time firing), including the author-exclusion check and the same mci-comparison column selection logic, so that `count_primary_aa_triggers` used for TPS-fee computation always matches (or over-approximates, never under-approximates) the number of triggers that will actually be processed and paid for.

## Proof of Concept
Not fully constructed — this requires confirming, via live tracing, whether a unit can simultaneously satisfy the `aa_addresses` output-count condition in `validateAATrigger` while failing the `NOT EXISTS (unit_authors JOIN aa_addresses)` guard (or vice versa) used in `handleAATriggers`, i.e., whether an author address can be an existing `aa_addresses` entry while also being able to legitimately author and post a payment unit. This determination was not completed within the available exploration budget.

### Citations

**File:** validation.js (L986-1038)
```javascript
async function validateAATrigger(conn, objUnit, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || objValidationState.bAA || !objValidationState.last_ball_mci) {
		if ("max_aa_responses" in objUnit)
			return callback(`max_aa_responses should not be there`);
		if (objValidationState.bAA || !objValidationState.last_ball_mci)
			return callback();
	}
	if ("content_hash" in objUnit) { // messages already stripped off
		objValidationState.count_primary_aa_triggers = 0;
		return callback();
	}
	if (objUnit.max_aa_responses === 0 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback(`max_aa_responses=0 is not allowed`);
	let outputCounts = {};
	for (let m of objUnit.messages) {
		if (m.app === 'payment' && m.payload) {
			const asset = m.payload.asset || 'base';
			for (let o of m.payload.outputs) {
				if (!outputCounts[o.address])
					outputCounts[o.address] = {};
				if (!outputCounts[o.address][asset])
					outputCounts[o.address][asset] = 0;
				outputCounts[o.address][asset]++;
			}
		}
	}
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
	callback();
```

**File:** validation.js (L1050-1071)
```javascript
async function validateTpsFee(conn, objJoint, objValidationState, callback) {
	if (objValidationState.last_ball_mci < constants.v4UpgradeMci || !objValidationState.last_ball_mci)
		return callback();
	const objUnit = objJoint.unit;
	if (objValidationState.bAA) {
		if ("tps_fee" in objUnit)
			return callback("tps_fee in AA response");
		return callback();
	}
	if ("content_hash" in objUnit) // tps_fee and other unit fields have been already stripped
		return callback();
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

**File:** storage.js (L1339-1349)
```javascript
async function getLocalTpsFee(conn, objUnitProps, count_units = 1) {
	const objLastBallUnitProps = await readUnitProps(conn, objUnitProps.last_ball_unit);
	const last_ball_mci = objLastBallUnitProps.main_chain_index;
	const base_tps_fee = getSystemVar('base_tps_fee', last_ball_mci); // unit's mci is not known yet
	const tps_interval = getSystemVar('tps_interval', last_ball_mci);
	const tps_fee_multiplier = getSystemVar('tps_fee_multiplier', last_ball_mci);
	const tps = await getLocalTps(conn, objUnitProps, count_units);
	console.log(`local tps at ${objUnitProps.unit} ${tps}`);
	const tps_fee_per_unit = Math.round(tps_fee_multiplier * base_tps_fee * (exp(tps / tps_interval) - 1));
	return count_units * tps_fee_per_unit;
}
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

**File:** main_chain.js (L1691-1723)
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
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
		);
	}
```
