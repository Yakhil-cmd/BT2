I have enough evidence to construct the analog now.

### Title
Uncaught exception during AA trigger message-template evaluation crashes the deterministic AA-trigger pipeline and bricks processing of all queued AA triggers - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `handleAATriggers()` loads *all* pending AA triggers from the `aa_triggers` table (posted by any unprivileged address that sends a unit to an AA) and processes them sequentially with `async.eachSeries`, one connection/transaction at a time, deleting each row from `aa_triggers` only after it is successfully handled. [1](#0-0) 
Within the per-trigger processing (`handleTrigger` → `evaluateAA` → `replace`), most error paths are funneled through a controlled `bounce()`/`cb(err)` mechanism, but several code paths use a raw, unguarded `throw Error(...)` instead of calling back with an error, e.g. the final fallback in `replace()`: [2](#0-1) 
and similar raw throws deeper in formula evaluation such as `assignByPath` and `callGetter`. [3](#0-2) [4](#0-3) 

This mirrors the reported bug class exactly: a queue (here, the `aa_triggers` table, processed strictly in mci/level/unit/address order) is processed element-by-element with no isolation/error-boundary around a step that can synchronously throw instead of gracefully failing, so a single malformed/edge-case element can abort processing of everything after it.

### Finding Description
`handleAATriggers` is the single entry point that drains the `aa_triggers` queue after a unit becomes stable, and it is invoked from `writer.js` right after stabilization, inside the same write pipeline used by every node to reach consensus: [5](#0-4) 
Processing is strictly sequential (`async.eachSeries`), and a trigger's row is deleted from `aa_triggers` (marking it "done") only inside the `onDone` callback of `handlePrimaryAATrigger`, after the whole `handleTrigger` pipeline finishes without throwing: [6](#0-5) 

Inside `handleTrigger`, the recursive `replace()` function walks the (post-formula-substitution) AA message template and is supposed to convert every intermediate error into a call to `cb(err)`, which is caught upstream and turned into a `bounce()` of just that one trigger. However, several branches instead perform a raw `throw`:
- `replace()`'s final `else` branch throws if a substituted value has an unexpected JS type: `throw Error('unknown type of value in ' + name);` [7](#0-6) 
- Formula evaluation helpers such as `assignByPath` (used when mutating local objects with selector assignment) throw on data shapes not otherwise rejected by pre-execution static validation: `throw Error("not an object: ...")`, `throw Error("scalar ... treated as object")`, etc. [8](#0-7) 
- `callGetter` throws `"args is not an array"` if bookkeeping around remote getter calls is violated. [4](#0-3) 

Because these are synchronous `throw` statements executed deep inside nested asynchronous callbacks (invoked from `async.eachSeries`/`async.eachOfSeries` iterators), they are not caught by any `try/catch` in the call chain and are not routed through the `bounce()`/`revert()` machinery that normally isolates a failing AA response. An uncaught exception of this kind propagates out of the event loop tick and (absent a matching top-level handler for this code path) terminates the Node.js process. Since AA trigger processing is fully deterministic and every full node must independently execute the exact same triggers in the exact same order to remain in consensus, a crash is not merely local: every node that reaches this trigger in the queue will crash in the same way, and upon restart will immediately re-select the same un-processed row from `aa_triggers` (it was never deleted) and crash again — permanently bricking the AA-trigger execution pipeline network-wide, not merely for the depositor who caused it, until node operators patch the software.

This is the same root-cause pattern as the reported ERC1155/Carousel issue — a sequential queue where processing one element can synchronously abort (via callback/hook) and prevents all subsequent already-queued elements from ever being processed — but in ocore the queue is the AA-trigger processing queue that services the entire network rather than one user's deposit queue, and the "no error handling in place" observation applies to the raw `throw` sites bypassing the `cb(err)`/`bounce()` protocol.

### Impact Explanation
If a trigger can be crafted (through an AA definition posted by any address plus a subsequent trigger unit sent by any address) that drives `replace()`/`evaluate()` into one of these raw-throw branches, the result is a crash of every full node that processes the block containing that trigger, and a permanent halt of all AA-trigger execution afterward (because the offending row remains queued and is retried identically on restart). This satisfies "a network unable to confirm new units" / "node disagreement on validity" root causes: light clients and full nodes can no longer progress AA state, and any funds or transfers routed through AAs are frozen indefinitely until the vulnerable code is patched and the stuck row is manually removed/fixed.

### Likelihood Explanation
Triggering an AA and posting AA definitions are both fully permissionless operations available to any unprivileged unit poster. The static formula validator (`formula/validation.js`) is intended to reject formulas that could reach the throwing branches, so exploitation requires finding a validation gap where a crafted formula/definition passes `validateDefinition`/formula validation but nonetheless produces, at evaluation time, a value/state that `replace()` or `assignByPath`/`callGetter` do not expect. Given the size and complexity of the oscript grammar and the number of independent throw sites bypassing the callback-error protocol, this is a plausible and historically common class of bug in this codebase (the existing `bounce()`-based error handling was clearly intended to cover exactly these cases, but is inconsistently applied).

### Recommendation
Audit every `throw Error(...)` reachable from `handleTrigger`/`evaluateAA`/`replace` and from `formula/evaluation.js` functions invoked during AA execution (`assignByPath`, `callGetter`, etc.), and convert them into calls to `cb(err)`/`setFatalError(...)` so they flow through the existing `bounce()` mechanism instead of throwing synchronously. Additionally, wrap the per-trigger processing in `handlePrimaryAATrigger`/`handleAATriggers` with a catch-all that, on any unexpected uncaught exception, safely aborts/bounces only the single offending trigger (and skips or dead-letters it) rather than allowing the exception to escape `async.eachSeries` and crash the process, so a single malformed trigger cannot permanently halt the entire AA queue for the whole network.

### Proof of Concept
Conceptual reproduction path (requires confirming a concrete formula/definition that survives `formula/validation.js` but reaches a raw throw at evaluation time):
1. Post an AA definition whose `getters`/`init`/message templates are engineered so that, for a specific trigger payload, `replace()` is invoked with a substituted value whose JS type is neither number/boolean/string/array/object-with-cases (e.g., `undefined`), reaching the `else throw Error('unknown type of value in ' + name)` branch at `aa_composer.js:871-872`. Alternatively, craft a selector-mutation (`$x[...] = ...`) whose runtime object shape passes static validation but violates the runtime invariants checked in `assignByPath` (`formula/evaluation.js:2870-2903`), e.g. attempting to add a non-numeric key to an array or to overwrite a previously-unset array slot.
2. Send a trigger unit invoking this AA from any address; wait for the unit (and thus the `aa_triggers` row) to stabilize.
3. Observe that `handleAATriggers` → `handlePrimaryAATrigger` → `handleTrigger` → `replace`/`evaluate` throws synchronously inside the `async.eachSeries` iterator instead of calling `cb(err)`, propagating as an uncaught exception that crashes the node process; the `aa_triggers` row is never deleted (delete happens only in the `onDone` callback), so every node hits the same crash on restart, permanently halting AA-trigger processing network-wide.

### Citations

**File:** aa_composer.js (L59-88)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
```

**File:** aa_composer.js (L91-106)
```javascript
function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
```

**File:** aa_composer.js (L870-872)
```javascript
		}
		else
			throw Error('unknown type of value in ' + name);
```

**File:** formula/evaluation.js (L2870-2903)
```javascript
	function assignByPath(obj, arrKeys, value) {
		if (typeof obj !== 'object')
			throw Error("not an object: " + obj);
		var pointer = obj;
		for (var i = 0; i < arrKeys.length - 1; i++){
			var key = arrKeys[i];
			if (key === null) { // special value to indicate the next element of an array
				if (!Array.isArray(pointer))
					throw Error("not an array: " + pointer);
				key = pointer.length;
			}
			if (!hasOwnProperty(pointer, key) || pointer[key] === null) {
				if (typeof key === 'number' && key > 0 && (pointer[key - 1] === undefined || pointer[key - 1] === null))
					throw Error("previous key value " + (key - 1) + " not set");
				if (Array.isArray(pointer) && typeof key !== 'number')
					throw Error(`adding a non-numeric key ${key} to an array: ${pointer}`);
				var next_key = arrKeys[i + 1];
				assignField(pointer, key, (typeof next_key === 'number' || next_key === null) ? [] : {});
			}
			else if (typeof pointer[key] !== 'object')
				throw Error("scalar " + pointer[key] + " treated as object");
			pointer = pointer[key];
		}

		var last_key = arrKeys[arrKeys.length - 1];
		if (last_key === null) { // special value to indicate the next element of an array
			if (!Array.isArray(pointer))
				throw Error("not an array: " + pointer);
			last_key = pointer.length;
		}
		if (typeof last_key === 'number' && last_key > 0 && (pointer[last_key - 1] === undefined || pointer[last_key - 1] === null))
			throw Error("previous key value " + (last_key - 1) + " not set");
		if (Array.isArray(pointer) && typeof last_key !== 'number')
			throw Error(`adding a non-numeric key ${last_key} to an array: ${pointer}`);
```

**File:** formula/evaluation.js (L3340-3341)
```javascript
			if (!Array.isArray(args))
				throw Error("args is not an array");
```

**File:** writer.js (L724-727)
```javascript
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();
```
