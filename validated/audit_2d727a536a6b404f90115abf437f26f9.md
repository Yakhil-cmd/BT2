## Title
`initSystemVars` re-initialization would corrupt in-memory system-var arrays used for TPS fee calculation - (File: storage.js)

## Summary
`storage.js`'s `initSystemVars(conn)` populates the in-memory `systemVars` cache (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) by `push`-ing every row read from the `system_vars` table onto the existing arrays, without ever clearing them first. This mirrors the reported bug class: a re-initialization path re-applies "genesis" state onto structures that should only ever be populated once, corrupting values that drive fee/gas-like calculations (here, TPS fee metering) instead of resetting to defaults, but with the same root cause — initialization code is not idempotent / not guarded against being invoked more than once. [1](#0-0) 

## Finding Description
`systemVars` is a module-level cache seeded once at declaration: [2](#0-1) 

`initSystemVars` is supposed to run exactly once, during `initCaches()` at node startup, and simply appends every row from `system_vars` (ordered by `vote_count_mci DESC`) into the corresponding `systemVars[subject]` array: [1](#0-0) 

Unlike the OP-list reset path in `countVotes()`, which explicitly does `storage.systemVars.op_list = [];` before rebuilding at `mci === 0`: [3](#0-2) 

`initSystemVars` has no such guard. If `initCaches()` (which calls `initSystemVars`) is ever invoked a second time in the life of a running process, every subject's array is contaminated with a second, duplicated (and possibly stale-ordered) copy of the history, because the arrays are never emptied: [4](#0-3) 

Downstream, `getSystemVar()` and the various TPS-fee helpers (`getLocalTpsFee`, `getFinalTpsFee`, `getCurrentTpsFee`, `getCurrentTpsFeeToPay`) all read from `systemVars[subject]` to determine `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` — the parameters that behave analogously to Optimism's `ResourceParams` (a moving/derived fee parameter that must stay authoritative and correctly ordered): [5](#0-4) [6](#0-5) [7](#0-6) 

These values feed directly into the TPS-fee validation consensus rule that every posted unit must satisfy: [8](#0-7) 

## Impact Explanation
Contrary to the external report's `ResourceParams` reset (which zeroes/loses fee state), this ocore analog **duplicates** history rather than reset it, but the effect is the same class of danger: **the metering parameter array driving fee-gating consensus logic is corrupted by a second call to initialization code**. Because `getSystemVar(subject, mci)` (implementation not fully visible in the explored index, but used consistently as "walk history array and pick entry valid at `mci`") depends on the array being properly ordered/deduplicated by `vote_count_mci`, duplicate entries could cause different nodes that happened to call `initCaches`/`initSystemVars` a different number of times (e.g. due to a light-to-full/administrative re-init path, or future code invoking `initCaches()` again after a catchup/reset event) to compute divergent `base_tps_fee`/`tps_interval`/`tps_fee_multiplier` for the same mci, or to read the wrong (older/duplicate) entry. That, in turn, would make TPS-fee validation (`validateTpsFee` in `validation.js`) diverge between nodes for the same unit, risking either **rejecting a legitimate unit on some nodes while accepting it on others (network disagreement on validity)**, or, since `min_tps_fee`/fee-balance checks depend on these values, potentially causing incorrect fee-balance/positive-balance accounting.

## Likelihood Explanation
I could not find, within index coverage, a concrete reachable trigger in the current codebase that calls `initCaches()`/`initSystemVars()` more than once during a running node's lifetime — the only located call site is the one-time startup call in `network.js`'s `startRelay()`. `resetMemory()` (used elsewhere, e.g. for cache resets after catchup or forced re-sync) explicitly does **not** call `initSystemVars`, only unstable/stable unit caches. Because of the ask-only index limitations, I was unable to fully verify all call sites of `initCaches`/`resetMemory` across the whole codebase (e.g. `tools/update_stability.js`, or light-client re-init flows) to confirm a concrete, attacker-reachable trigger for a second `initSystemVars()` call. Given the missing hard proof of an externally-triggerable double-init path, likelihood is Low-to-Medium; the root-cause code smell (non-idempotent initializer appending instead of resetting) is real and matches the reported bug class, but I cannot confirm consensus-breaking reachability from a single posted unit/trigger without further investigation of every `initCaches`/`resetMemory` call site.

## Recommendation
Make `initSystemVars` idempotent, matching the pattern already used for `op_list` resets in `main_chain.js`:
```js
async function initSystemVars(conn) {
	for (let subject in systemVars)
		systemVars[subject] = []; // ensure clean state on (re)initialization
	const rows = await conn.query("SELECT subject, value, vote_count_mci, is_emergency FROM system_vars ORDER BY vote_count_mci DESC");
	...
}
```
This guarantees that no matter how many times `initCaches()`/`initSystemVars()` is invoked, the in-memory system-var history used for TPS-fee metering remains authoritative and consistent across all nodes.

## Proof of Concept
Not fully constructible from the indexed code alone: a concrete PoC requires demonstrating a code path that calls `storage.initCaches()` (or `initSystemVars()` directly) a second time on a live node. This was not confirmed within the explored index — see Likelihood Explanation. Conceptually, the flaw can be demonstrated in isolation by calling `initSystemVars(conn)` twice against the same connection and observing `storage.systemVars.base_tps_fee` (and other subjects) containing duplicate entries, after which `getSystemVar('base_tps_fee', mci)` may return an incorrect entry for some `mci` values depending on the picking logic's tolerance for duplicates/ordering.

### Citations

**File:** storage.js (L46-52)
```javascript
let systemVars = {
	op_list: [],
	threshold_size: [],
	base_tps_fee: [],
	tps_interval: [],
	tps_fee_multiplier: [],
};
```

**File:** storage.js (L1238-1245)
```javascript
function getFinalTpsFee(objUnitProps) {
	const mci = objUnitProps.main_chain_index;
	const base_tps_fee = getSystemVar('base_tps_fee', mci); // not at last_ball_mci
	const tps_interval = getSystemVar('tps_interval', mci);
	const tps = getFinalTps(objUnitProps);
	console.log(`final tps at ${objUnitProps.unit} ${tps}`);
	return Math.round(base_tps_fee * (exp(tps / tps_interval) - 1));
}
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

**File:** storage.js (L1397-1408)
```javascript
function getCurrentTpsFee(shift = 0, count_units = 1) {
	const tps = getCurrentTps(shift, count_units);
	console.log(`current tps with shift ${shift} ${tps}`);
	const base_tps_fee = getSystemVar('base_tps_fee', last_stable_mci);
	const tps_interval = getSystemVar('tps_interval', last_stable_mci);
	return Math.round(base_tps_fee * (exp(tps / tps_interval) - 1));
}

function getCurrentTpsFeeToPay(shift = 0, count_units = 1) {
	const tps_fee_multiplier = getSystemVar('tps_fee_multiplier', last_stable_mci);
	return Math.round(tps_fee_multiplier * getCurrentTpsFee(shift, count_units));
}
```

**File:** storage.js (L2474-2484)
```javascript
async function initSystemVars(conn) {
	const rows = await conn.query("SELECT subject, value, vote_count_mci, is_emergency FROM system_vars ORDER BY vote_count_mci DESC");
	if (rows.length === 0)
		throw Error("no system vars");
	for (let { subject, value, vote_count_mci, is_emergency } of rows)
		systemVars[subject].push({ vote_count_mci, value: subject === 'op_list' ? JSON.parse(value) : +value, is_emergency });
	for (let subject in systemVars)
		if (systemVars[subject].length === 0)
			throw Error(`no ${subject} system vars`);
	console.log('system vars', systemVars);
}
```

**File:** storage.js (L2532-2547)
```javascript
async function initCaches() {
	console.log('initCaches');
	const unlock = await mutex.lock(["write"]);
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	await initSystemVars(conn);
	await initUnstableUnits(conn);
	await initStableUnits(conn);
	await initUnstableMessages(conn);
	await initHashTreeBalls(conn);
	console.log('initCaches done');
	if (!conf.bLight && constants.bTestnet)
		archiveJointAndDescendantsIfExists('K6OAWrAQkKkkTgfvBb/4GIeN99+6WSHtfVUd30sen1M=');
	await conn.query("COMMIT");
	conn.release();
	unlock();
```

**File:** main_chain.js (L1866-1870)
```javascript
			if (mci === 0) {
				storage.resetWitnessCache();
				storage.systemVars.op_list = []; // reset
			}
			storage.systemVars.op_list.unshift({ vote_count_mci: mci === 0 ? -1 : mci, value: ops, is_emergency });
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
