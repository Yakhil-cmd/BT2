### Title
Unbounded iteration over `assocUnstableUnits` in `storage.getCurrentTps()` causes per-unit validation cost to grow with unconfirmed-unit backlog, enabling a validation-throughput DoS - (File: `storage.js`)

### Summary
`storage.getCurrentTps()` loops over the entire in-memory `assocUnstableUnits` map on every call, and this function is invoked as part of `validateTpsFee()`, which runs during the validation of **every single unit** posted to the node (not once a day, as in the original report's `assessStates()`). Since `assocUnstableUnits` grows with every unit that has been accepted but not yet stabilized, and shrinks only when units stabilize, an attacker who keeps the unstable-unit set large (e.g., by flooding many valid, low-value units into parallel/non-witnessed branches faster than the stabilization process can retire them) causes the per-unit validation cost to grow linearly with the size of that backlog, degrading node throughput for validating any new unit.

### Finding Description
Every accepted (but not-yet-stable) unit is added to `storage.assocUnstableUnits` in `writer.js`: [1](#0-0) 
and it is only removed once its MCI is marked stable in `main_chain.markMcIndexStable()`: [2](#0-1) 

`storage.getCurrentTps()` fully iterates this map for every call: [3](#0-2) 

This function is reached from `getCurrentTpsFee()` → `getCurrentTpsFeeToPay()`, which is called during `validateTpsFee()`, a step executed for every unit going through the standard `validation.validate()` pipeline for every posted unit: [4](#0-3) [5](#0-4) 

Unlike the audited `DefaultStateManager.assessStates()` bug (a daily batch job iterating an ever-growing `protectionPoolStates` array), this ocore analog is worse in exposure: the unbounded loop runs on the **hot path of every unit validation**, meaning O(n) work per unit where n is the size of the current unstable-unit backlog, for a total O(n²) cost across n backlogged units.

### Impact Explanation
If the unstable-unit set grows large — which can happen whenever a poster (or several colluding posters) floods the DAG with many valid units in branches that are slow to be included/witnessed on the main chain, or more generally whenever confirmation throughput temporarily lags behind unit submission rate — every subsequent unit validated by any node must pay a cost proportional to the full backlog size. This degrades the node's ability to validate and thus confirm new units in a timely manner, matching the "network unable to confirm new units" impact category: nodes fall further and further behind as the backlog compounds, and legitimate senders experience growing latency/failure to get their units validated.

### Likelihood Explanation
Reaching this code path requires nothing more than posting ordinary valid units (an unprivileged poster action) after the v4 TPS-fee upgrade is active (`constants.v4UpgradeMci`). No special privileges, malicious peer/hub behavior, or protocol violations are needed — an attacker only needs to sustain unit submission in a manner that keeps many units unstable simultaneously (e.g. wide, poorly-included branches), which is entirely within reach of a normal unit poster.

### Recommendation
Avoid a full linear scan of `assocUnstableUnits` on every validation. Maintain an incrementally-updated running counter/aggregate (e.g., total count of TPS-fee-paying units and the earliest relevant timestamp) that is updated when units are added to/removed from `assocUnstableUnits`, instead of recomputing it from scratch for every unit validated in `getCurrentTps()`. Alternatively, cache the result of `getCurrentTps()` for a short time window (e.g., a few seconds) since the metric does not need per-unit precision.

### Proof of Concept
1. After the v4 TPS-fee upgrade activates, an actor submits a sustained stream of valid units that intentionally form wide, non-mainstream branches (e.g., minimal-fee units authored with unique addresses referencing older parents), so that many units remain in `assocUnstableUnits` simultaneously (`writer.js:597`) rather than quickly stabilizing.
2. Every additional unit — from the attacker or any other user — that arrives for validation triggers `validateTpsFee()` → `storage.getCurrentTpsFee()` → `getCurrentTps()`, which iterates the full, now-large `assocUnstableUnits` map (`storage.js:1368-1377`).
3. As the backlog keeps growing (submission rate > stabilization rate), each new unit's validation cost increases, degrading overall node throughput for confirming any unit on the network — the same class of unbounded-loop DoS as the original `assessStates()` finding, but reachable via ordinary unit posting rather than pool creation, and triggered on every unit validation rather than a daily cron job.

### Citations

**File:** writer.js (L596-597)
```javascript
			else
				storage.assocUnstableUnits[objUnit.unit] = objNewUnitProps;
```

**File:** main_chain.js (L1296-1307)
```javascript
	for (var unit in storage.assocUnstableUnits){
		var o = storage.assocUnstableUnits[unit];
		if (o.main_chain_index === mci && o.is_stable === 0){
			o.is_stable = 1;
			storage.assocStableUnits[unit] = o;
			storage.assocStableUnitsByMci[mci].push(o);
			arrStabilizedUnits.push(unit);
		}
	}
	arrStabilizedUnits.forEach(function(unit){
		delete storage.assocUnstableUnits[unit];
	});
```

**File:** storage.js (L1361-1377)
```javascript
function getCurrentTps(shift = 0, count_units = 1) {
	if (last_stable_mci === null)
		throw Error(`getCurrentTps: last_stable_mci not set yet`);
	const since_mci = last_stable_mci + shift;
	let count = count_units; // include the current unit and its AA responses
	let since_timestamp = 0;
	const now = Math.ceil(Date.now() / 1000);
	for (let unit in assocUnstableUnits) {
		const objUnitProps = assocUnstableUnits[unit];
		if (objUnitProps.timestamp > now) continue; // skip future-timestamped units
		if (objUnitProps.main_chain_index > since_mci || objUnitProps.main_chain_index === null)
			count += getCountUnitsPayingTpsFee(objUnitProps);
		else if (shift > 0 && objUnitProps.main_chain_index === since_mci) {
			if (objUnitProps.timestamp > since_timestamp)
				since_timestamp = objUnitProps.timestamp;
		}
	}
```

**File:** validation.js (L429-434)
```javascript
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
```

**File:** validation.js (L1050-1077)
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
	console.log('validation', {min_tps_fee}, objUnitProps)
	
	// compare against the current tps fee or soft-reject
	const current_tps_fee = objJoint.ball ? 0 : storage.getCurrentTpsFee(0, count_units); // very low while catching up
	const min_acceptable_tps_fee_multiplier = objJoint.ball ? 0 : storage.getMinAcceptableTpsFeeMultiplier();
	const min_acceptable_tps_fee = current_tps_fee * min_acceptable_tps_fee_multiplier * count_units;
```
