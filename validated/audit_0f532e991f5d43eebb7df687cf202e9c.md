## Title
`validateTpsFee` can crash unit validation via unhandled `throw` in `getLocalTps`/`getCurrentTps`, unlike the report's "MUST NOT revert" view function - ([File: validation.js], [File: storage.js])

### Summary
The Sherlock report flags `totalAssets()` for violating the EIP4626 "MUST NOT revert" rule because it transitively calls a function (`calculateInterest`/`getPendingInterest`) that can throw under conditions the caller does not fully control (insufficient gas relative to a fixed internal threshold), causing a supposedly safe read path to abort unpredictably. The analogous pattern in ocore is `validateTpsFee`, a mandatory step in the unit-validation pipeline that every posted unit must pass, which calls into `storage.getLocalTpsFee` → `storage.getLocalTps` and `storage.getCurrentTpsFee` → `storage.getCurrentTps`. These are supposed to be deterministic fee-calculation helpers that either return a number or reject the unit gracefully through the `callback(err)` convention used everywhere else in `validation.js`. Instead, they contain unconditional `throw Error(...)` statements guarded by internal consistency assumptions about node-local, time-dependent, in-memory state (`assocUnstableUnits`, `Date.now()`, parent/witness graph shape).

### Finding Description
`validateTpsFee` is invoked from the core unit validation flow for any unit whose `last_ball_mci` is at or after `constants.v4UpgradeMci` and which is not itself an AA response [1](#0-0) . It computes `min_tps_fee` via `storage.getLocalTpsFee`, and compares against `storage.getCurrentTpsFee` [2](#0-1) .

`getLocalTps` walks the unit's parent graph up to the last stable ball and asserts an invariant that must always find at least one TPS-paying ancestor; if that invariant is violated, it throws rather than returning a validation error to the caller: [3](#0-2) 

Similarly, `getCurrentTps` computes fees based on `assocUnstableUnits` (a purely in-memory, per-node cache) and the current wall-clock time, and throws in multiple internal-consistency branches (`last_stable_mci not set yet`, `no stable units at last stable mci`, `since_timestamp = 0`) instead of degrading gracefully: [4](#0-3) 

These throws are not wrapped in try/catch anywhere in the call chain (`getLocalTpsFee` at [5](#0-4)  and `validateTpsFee` at [6](#0-5) ), so an exception here escapes the normal `callback(errorMessage)` validation-rejection path used for every other check in the file, and instead surfaces as an unhandled exception (for `getCurrentTps`, a synchronous throw inside an `async function`, producing an unhandled promise rejection). This mirrors the report's core complaint: a function whose contract implies "must not throw/revert" during a routine, externally-triggerable read/validation path is written in a way that assumes conditions the untrusted caller (or divergent in-memory node state) doesn't guarantee.

### Impact Explanation
Because `getCurrentTps`/`getRecentTps` depend on `assocUnstableUnits`, wall-clock time, and each node's private in-memory bookkeeping rather than purely on stable, agreed-upon DAG state, two honest nodes validating the identical incoming unit at slightly different moments (different sets of currently-unstable units, different local time, different progress through catch-up) can reach different code paths: one computes a fee and accepts/rejects the unit normally, another hits one of the `throw` branches and crashes/aborts validation of that unit (or the whole validation batch) instead of returning a deterministic accept/reject decision. Likewise, `getLocalTps`'s invariant throw is derived from the unit's own parent-selection graph, which an ordinary unit poster influences when composing/broadcasting a unit; a constructed unit whose only qualifying parent chain violates the count-invariant would crash validation for that submitter's transaction. This is a genuine deviation from "view/validation helpers must not revert" and its impact class matches the report's category: unpredictable failure of a function expected to be robust, here inside consensus-critical validation rather than a read-only balance query — a stronger context because it can produce inconsistent accept/reject behavior between nodes on the same input, or an unhandled crash that prevents a node from confirming otherwise-valid units.

### Likelihood Explanation
The `getLocalTps` invariant throw is technically reachable by any unit poster who controls the choice of parent units feeding into their transaction, since `count === count_units` can occur if none of the ancestor units between the new unit and `last_ball_mci` are non-AA units — a condition that becomes more plausible as more traffic in the DAG comes from AA responses (excluded from the count) and TPS-fee accounting matures. The `getCurrentTps` throws are gated behind edge cases in the in-memory unstable-unit set and timestamp bookkeeping (`since_timestamp === 0` when there ARE non-zero counted units but no stable/unstable unit timestamps recorded), which are less trivially triggerable on demand but are plausible during node restart/catch-up windows or unusual timestamp sequences, and are not protected by any defensive check before the throw. I was not able to fully enumerate every DAG/topology precondition that forces `count === count_units` or `since_timestamp === 0` without running the code against live chain state, so likelihood should be treated as "reachable under specific, constructible conditions" rather than trivially reproducible in every network state.

### Recommendation
Treat `getLocalTps`, `getCurrentTps`, and their fee wrappers as functions that must never throw during ordinary unit validation. Replace the internal-consistency `throw Error(...)` calls in `storage.js` (lines 1316, 1335, 1362, 1383, 1391) with either: (a) propagation of a proper validation-rejection value/error through `getLocalTpsFee`/`getCurrentTpsFee`'s return contract so `validateTpsFee` can call `callback(err)` instead of letting an exception escape, or (b) explicit, deterministic fallback values (e.g., treat as `count_units`/zero elapsed with a safe default fee) so no two honest nodes can diverge on whether a given unit is valid. Additionally, wrap the entire `getLocalTpsFee`/`getCurrentTpsFee` computation in `validateTpsFee` with a try/catch that converts unexpected exceptions into a soft/transient validation error (as is already done elsewhere via `createTransientError`) rather than allowing them to bubble up as unhandled exceptions.

### Proof of Concept
Concrete conditions demonstrating the reachable throw branches (derived from code inspection, not a live-network reproduction):
1. In `getLocalTps`, walk the parent chain of a newly composed unit up from `last_ball_mci`; if every ancestor unit encountered before reaching `last_ball_mci` is an AA response (`parentProps.bAA === true`, excluded from `count`), then `count === count_units` at the end of the loop, and with `last_ball_mci > 0` and `constants.COUNT_WITNESSES > 1` (always true on mainnet), the function throws instead of returning a value [7](#0-6) , which propagates unhandled out of `validateTpsFee` [8](#0-7) .
2. In `getCurrentTps`, if `assocUnstableUnits` contains only units with `main_chain_index > since_mci` (all counted in `count`) while `assocStableUnitsByMci[last_stable_mci]` unexpectedly has no entries with a positive timestamp (a state achievable during certain catch-up/replay sequences), `since_timestamp` remains `0` and the function throws `since_timestamp = 0, ...` [9](#0-8) , again with no try/catch anywhere in the call chain up to `validateTpsFee`.

Because both throws occur inside a mandatory step of the standard unit-validation flow (`validateTpsFee`, called for essentially every unit past `v4UpgradeMci`), they violate the implicit expectation that validation helpers return a deterministic accept/reject decision rather than crash — the ocore analog of `totalAssets()` "MUST NOT revert."

### Citations

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

**File:** storage.js (L1303-1336)
```javascript
async function getLocalTps(conn, objUnitProps, count_units = 1) {
	const unit = objUnitProps.unit;
	const objLastBallUnitProps = await readUnitProps(conn, objUnitProps.last_ball_unit);
	const elapsed = (objUnitProps.timestamp - objLastBallUnitProps.timestamp) || elapsedTimeWhenZero;
	const last_ball_mci = objLastBallUnitProps.main_chain_index;
	let count = count_units;
	let visited = {};
	let arrProps = [objUnitProps];

	while (true) {
		let arrParentProps = [];
		for (let props of arrProps) {
			if (!props.best_parent_unit)
				throw Error(`no best parent in props of ${props.unit}`);
			const parent_units = props.unit === unit ? [props.best_parent_unit] : props.parent_units;
			for (let parent_unit of parent_units) {
				if (visited[parent_unit])
					continue;
				const parentProps = await readUnitPropsWithParents(conn, parent_unit);
				if (parentProps.main_chain_index <= last_ball_mci && parentProps.main_chain_index !== null)
					continue;
				if (!parentProps.bAA) // AA responses are counted elsewhere via max_aa_responses of their trigger
					count += getCountUnitsPayingTpsFee(parentProps);
				visited[parent_unit] = true;
				arrParentProps.push(parentProps);
			}
		}
		if (arrParentProps.length === 0)
			break;
		arrProps = arrParentProps;
	}
	if (count === count_units && last_ball_mci > 0 && constants.COUNT_WITNESSES > 1)
		throw Error(`getLocalTps count=${count}, elapsed=${elapsed}, ${JSON.stringify(objUnitProps)}`);
	return count / elapsed;
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

**File:** storage.js (L1361-1395)
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
	if (count === count_units)
		return 0;
	//	throw Error(`getCurrentTps: no unstable units`);
	if (shift === 0) {
		const arrLastStableUnitProps = assocStableUnitsByMci[last_stable_mci];
		if (!arrLastStableUnitProps)
			throw Error(`getCurrentTps: no stable units at last stable mci ${last_stable_mci}`);
		for (let { timestamp } of arrLastStableUnitProps) {
			if (timestamp > since_timestamp)
				since_timestamp = timestamp;
		}
	}
	if (since_timestamp === 0)
		throw Error(`since_timestamp = 0, shift=${shift}, last_stable_mci=${last_stable_mci}`)
	const elapsed = (Math.round(Date.now() / 1000) - since_timestamp) || elapsedTimeWhenZero;
	console.log(`getCurrentTps shift=${shift}, date ${new Date()}, diff ${Math.round(Date.now() / 1000) - since_timestamp} ${count}/${elapsed}`);
	return count / elapsed;
}
```
