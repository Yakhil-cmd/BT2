### Title
Uncaught exception in `validateTpsFee`/`getLocalTps` permanently halts unit validation for the entire network - (File: `validation.js`, `storage.js`)

### Summary
`validateTpsFee()` is invoked as an unconditional step of every non-AA unit's validation once past the v4.0 TPS-fee upgrade, exactly analogous to how `RToken.issue()` unconditionally calls `furnace.melt()` in the original finding. Deep inside this call chain, `storage.getLocalTps()` contains a bare `throw Error(...)` guarded by a state condition (`count === count_units`) that depends on the DAG structure an attacker fully controls when composing a unit (its `parent_units`/`last_ball_unit`). Because the call is made from an `async function` used as if it were a plain callback-style function (never `await`ed, never `.catch()`ed), the thrown error becomes an unhandled promise rejection, which — with no global `unhandledRejection` handler present in production code — crashes the Node.js process validating the unit.

### Finding Description
`validate()` runs `validateTpsFee` unconditionally for every regular unit as one step of its `async.series`: [1](#0-0) 

`validateTpsFee` is declared `async` and is called with a plain node-style callback wrapper `function (cb) { validateTpsFee(conn, objJoint, objValidationState, cb); }` — its returned promise is never awaited or `.catch()`-handled by the caller: [2](#0-1) 

It unconditionally calls `storage.getLocalTpsFee`, which calls `getLocalTps`: [3](#0-2) 

`getLocalTps` walks the best-parent/parent chain of the unit being validated, incrementing `count` for every unstable, non-AA, fee-paying unit found before hitting an already-stable ancestor. If that walk never increments `count` beyond `count_units` (i.e., the unit's best parent — and any other parent — is already stable at or below `last_ball_mci`), it hits a bare `throw`: [4](#0-3) 

This mirrors the RToken bug class precisely: a shared, unconditionally-invoked internal function (`furnace.melt()` in RToken; `getLocalTps` in ocore) embedded in the critical entry path (`issue()`; `validate()`), which can be driven into a revert/throw by state that a low-privilege actor (an "early attacker") can shape (small rToken transfer to the furnace; crafting `parent_units`/`last_ball_unit` of a posted unit), with **no try/catch** around the call. In RToken the effect is a revert that blocks all future `issue()` calls; in ocore, because the unconditional call is an unguarded `async` function invoked without `await`/`.catch()`, the effect is worse: an **uncaught exception that crashes the node process** validating the unit.

### Impact Explanation
Since `validate()` is executed by every full node on every unit it receives (from any peer, including units originated by an unprivileged unit poster and then propagated over the P2P network), a single crafted unit that trips this throw crashes every node that attempts to validate it. This is not a network-layer flood or peer/hub-specific attack — it is a pure consensus/validation-logic bug reachable by anyone able to compose and broadcast one ordinary unit, and its effect is "a network unable to confirm new units," which is one of the explicitly accepted impact categories for this scan. This is more severe than the original Medium-severity RToken finding (permanent revert of a single function) because it results in process termination across nodes.

### Likelihood Explanation
The precondition (`count === count_units`, i.e., the new unit's best parent — and any other included parent — is already stable at or below the referenced `last_ball_mci`) is a structural DAG condition. An unprivileged unit poster fully controls the `parent_units` and `last_ball_unit` fields of a unit it composes/broadcasts, subject only to the checks that run earlier in the same `async.series` (`validateParentsExistAndOrdered`, `validateHashTreeParentsAndSkiplist`, `validateParents`), none of which reject a unit whose best parent is already stable. I was not able to fully confirm end-to-end, with a live node, that all of those preceding checks can be satisfied simultaneously with the `count === count_units` condition — this requires deeper DAG-state modeling or live testing than is possible from static code review alone, so likelihood should be validated with a concrete PoC before treating this as fully proven.

### Recommendation
- Wrap the call to `validateTpsFee` (and any other `async function` invoked as a callback-style function inside `validate()`'s `async.series`) so that promise rejections are properly caught and converted into a normal validation error passed to `cb(err)`, e.g. `validateTpsFee(...).then(...).catch(err => cb(err.message || String(err)))`.
- Replace the internal `throw Error(...)` sanity check in `getLocalTps` (storage.js ~line 1334-1335) with a recoverable error path (return an error to the caller) rather than an unconditional throw, since this function is reachable from unit validation with attacker-influenced inputs.
- Add a process-level `unhandledRejection` handler as defense-in-depth so that a stray async error in any validation code path degrades gracefully (e.g., logs and rejects the specific unit) instead of crashing the entire node.

### Proof of Concept
Conceptual PoC (exact DAG construction not verified live):
1. Attacker composes and signs an ordinary (non-AA) unit whose `parent_units` reference the current best tip and whose `last_ball_unit`/`last_ball` are chosen such that, when `getLocalTps` walks from this new unit's `best_parent_unit`, that parent's `main_chain_index` is already `<= last_ball_mci` (i.e., no unstable, fee-paying ancestor exists between the new unit and its last ball).
2. Attacker broadcasts the unit to the network.
3. Every node that receives it runs `validate()` → `validateTpsFee()` → `storage.getLocalTpsFee()` → `getLocalTps()`.
4. `getLocalTps` computes `count === count_units` and executes `throw Error(...)` inside an unawaited `async function` chain, producing an unhandled promise rejection.
5. Absent a global `unhandledRejection` handler in the production code (only test files register one), the Node.js process crashes, and repeats for every node that later processes the same unit — halting the network's ability to confirm new units until the code is patched.

### Citations

**File:** validation.js (L429-434)
```javascript
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
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
