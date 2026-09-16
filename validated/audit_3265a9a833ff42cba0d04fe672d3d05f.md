## Title
Negative "elapsed" time in local TPS-fee calculation from an attacker-controlled unit timestamp lower than its last-ball timestamp - ([File: storage.js])

### Summary
The external report describes an underflow when an oracle price's off-chain timestamp is larger than the current on-chain timestamp, which turns a subtraction (`now - price_timestamp`) negative and breaks a staleness/elapsed-time computation. The closest reachable analog in ocore is the local TPS-fee "elapsed time" computation, which is likewise `unit.timestamp - last_ball_unit.timestamp` and is not protected against the unit's own `timestamp` field being set lower than (or even far below) its `last_ball_unit`'s timestamp.

### Finding Description
`getLocalTps()` and `getFinalTps()` in storage.js compute:
```
const elapsed = (objUnitProps.timestamp - objLastBallUnitProps.timestamp) || elapsedTimeWhenZero;
``` [1](#0-0) [2](#0-1) 

`objUnitProps.timestamp` is the unit's self-declared `timestamp` field, and `objLastBallUnitProps.timestamp` is the timestamp of the stable unit referenced as `last_ball_unit`. Unit-level timestamp validation in validation.js only bounds the timestamp from above (rejecting timestamps too far in the future); it does not enforce that a unit's own timestamp is greater than or equal to the timestamp of the `last_ball_unit` it references: [3](#0-2) 

Because an author fully controls their own unit's `timestamp` (subject only to the "not more than N seconds in the future" check), a unit poster can pick an old `last_ball_unit` with a large timestamp and then set their own unit's `timestamp` to something smaller than that last-ball timestamp, producing a negative `elapsed` value in `getLocalTps`/`getFinalTps`.

This negative `elapsed` then flows into `getLocalTpsFee()`:
```
const tps = await getLocalTps(conn, objUnitProps, count_units);
const tps_fee_per_unit = Math.round(tps_fee_multiplier * base_tps_fee * (exp(tps / tps_interval) - 1));
``` [4](#0-3) 
`count / elapsed` with a negative `elapsed` produces a negative `tps`, which drives `exp(tps/tps_interval) - 1` toward `-1`, yielding a negative (or artificially minimal) `tps_fee_per_unit`. This is used directly as `min_tps_fee` in `validateTpsFee()`: [5](#0-4) 
which checks that `tps_fees_balance + objUnit.tps_fee * share >= min_tps_fee * share`. A negative/near-zero `min_tps_fee` trivially passes this check even when the unit pays no or minimal `tps_fee`.

### Impact Explanation
The tps-fee mechanism is the network's economic throttle against congestion (its purpose is to make posting units under load require a scaling fee). By crafting timestamps that push `elapsed` negative, an ordinary unit poster can force `getLocalTpsFee` to return an artificially low or negative required fee, bypassing the intended anti-spam/anti-congestion economics enforced in `validateTpsFee`. This does not directly steal funds or break AA logic, but it undermines the mechanism designed to keep the network able to confirm units fairly under load — a network-availability class impact.

### Likelihood Explanation
Exploitability is limited by the fact that `objUnitProps.timestamp` must still satisfy the "not too far in the future" unit-validation rule and it must be consistent among the unit's own DAG position, but there is no explicit floor requiring `objUnit.timestamp >= objLastBallUnitProps.timestamp`. Because ocore does not appear to enforce monotonic ordering between a unit's timestamp and its referenced last-ball unit's timestamp elsewhere in `validation.js` (confirmed by exhaustive search of `timestamp` usages there), a sufficiently motivated single unit-poster could attempt to trigger this. However, I was unable to fully confirm (within tool/search limits) whether there is a separate consistency check elsewhere in the codebase (e.g., in composer.js or parent selection logic) that indirectly prevents choosing a `last_ball_unit` with a timestamp greater than the new unit's own timestamp when units are honestly composed; the guard would only be bypassable by a unit poster who directly crafts and posts a raw unit (bypassing the normal composer), which the threat model in this exercise (unprivileged unit poster) permits.

### Recommendation
- In `getLocalTps` / `getFinalTps` / `getLocalTpsFee` (storage.js), clamp `elapsed` to a minimum positive value (e.g., `Math.max(elapsed, elapsedTimeWhenZero)`) instead of only special-casing exactly `0` via `|| elapsedTimeWhenZero`, so a negative elapsed cannot occur.
- Additionally/alternatively, enforce in unit validation (`validation.js`) that a unit's `timestamp` must be `>=` the timestamp of its `last_ball_unit` (mirroring the fix pattern in the referenced Synthetix commit, which added an explicit floor/staleness guard rather than relying on an unguarded subtraction).

### Proof of Concept
1. An attacker composes a raw unit (bypassing the normal wallet composer) whose `last_ball_unit` points to a stable unit with a large `timestamp` (e.g., `T_ref`).
2. The attacker sets their own unit's `timestamp` field to a small value `T_new < T_ref` (still satisfying the "not more than N seconds into the future" rule, since that rule only bounds the upper side).
3. When this unit becomes the trigger for `getLocalTpsFee`/`validateTpsFee`, `elapsed = T_new - T_ref` is negative.
4. `getLocalTps` returns `count / elapsed` (negative), and `getLocalTpsFee` computes a negative/near-zero `tps_fee_per_unit`, lowering `min_tps_fee` in `validateTpsFee` far below the value that should be required under real network load, allowing the unit to pass the tps-fee check while paying little or no fee.

### Citations

**File:** storage.js (L1176-1185)
```javascript
function getFinalTps(objUnitProps) {
	const unit = objUnitProps.unit;
	const mci = objUnitProps.main_chain_index;
	console.log('getFinalTps', unit, mci);
	const objMcUnitProps = getMcUnitProps(mci);
	const objLastBallUnitProps = assocStableUnits[objMcUnitProps.last_ball_unit];
	if (!objLastBallUnitProps)
		throw Error(`no last ball of MC unit ${objMcUnitProps.unit} found in cache`);
	const elapsed = (objMcUnitProps.timestamp - objLastBallUnitProps.timestamp) || elapsedTimeWhenZero;
	const last_ball_mci = objLastBallUnitProps.main_chain_index;
```

**File:** storage.js (L1303-1307)
```javascript
async function getLocalTps(conn, objUnitProps, count_units = 1) {
	const unit = objUnitProps.unit;
	const objLastBallUnitProps = await readUnitProps(conn, objUnitProps.last_ball_unit);
	const elapsed = (objUnitProps.timestamp - objLastBallUnitProps.timestamp) || elapsedTimeWhenZero;
	const last_ball_mci = objLastBallUnitProps.main_chain_index;
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

**File:** validation.js (L280-287)
```javascript
	if (objUnit.version !== constants.versionWithoutTimestamp) {
		if (!isPositiveInteger(objUnit.timestamp))
			return callbacks.ifUnitError("timestamp required in version " + objUnit.version);
		var current_ts = Math.round(Date.now() / 1000);
		var max_seconds_into_the_future_to_accept = conf.max_seconds_into_the_future_to_accept || 5;
		if (objUnit.timestamp > current_ts + max_seconds_into_the_future_to_accept)
			return callbacks.ifTransientError("timestamp is too far into the future");
	}
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
