### Title
Lock-Order Inversion Between Per-Address Validation Lock and Global "write" Lock Causes Permanent Deadlock, Halting All Unit Confirmation - ([File: validation.js])

### Summary
`ocore`'s `mutex.js` implements a simple key-based lock manager where a lock request that overlaps any currently-held key is queued until the key is released, with no deadlock detection enabled in production (`checkForDeadlocks` is commented out). Two independent code paths acquire the per-author-address lock and the global `"write"` lock in opposite order, which can be triggered by an ordinary unit poster combined with an Autonomous Agent (AA) response, producing a classic AB-BA deadlock — directly analogous to CVE-2015-8767, where the Linux SCTP subsystem mismanaged the relationship between a lock and a resource (the socket), causing a permanent deadlock reachable via `sctp_accept`.

### Finding Description
`validation.validate()` locks the posted unit's author addresses for the entire duration of validation, and this lock is only released after the unit has also been written to the database: [1](#0-0) 

In `network.js`'s `handleJoint`, the `ifOk` callback calls `writer.saveJoint(...)` while still holding the author-address lock, and only releases it (`validation_unlock()`) inside `saveJoint`'s completion callback — i.e., after the global `"write"` lock has been fully acquired, used, and released: [2](#0-1) 

`writer.saveJoint()` itself acquires the process-wide `"write"` mutex before doing any database work: [3](#0-2) 

Critically, while still holding this `"write"` lock (the `unlock()` call happens later, after the stabilization loop), `saveJoint` can synchronously trigger AA execution via `aa_composer.handleAATriggers()`: [4](#0-3) 

`handleAATriggers` → `handlePrimaryAATrigger` → `validateAndSaveUnit` calls `validation.validate()` again for the AA's own response unit, passing the external DB connection and effectively re-entering the same author-address locking logic — this time for the **AA's own address**, while the `"write"` lock is already held: [5](#0-4) [6](#0-5) 

This creates two conflicting lock-acquisition orders across the codebase:
- Path A (normal unit validation): acquire `[author-address]` → later acquire `["write"]` (held nested, released only when the address lock is released).
- Path B (AA trigger execution nested in an in-progress save): acquire `["write"]` → later acquire `[AA-address]`.

If an attacker crafts and posts an ordinary unit whose author address equals an AA address that is due to be triggered by a *different, already in-flight* unit (Path B), the following interleaving becomes possible:
1. Unit U1 (Path B) is being saved and holds `["write"]`; while still holding it, `saveJoint` starts executing AA triggers and needs to lock `[AA-address]`.
2. Concurrently, an attacker-crafted unit U2 whose sole author is exactly that `AA-address` is being validated via `handleJoint` (Path A); it has already acquired `[AA-address]` and is now blocked waiting for `["write"]` inside `writer.saveJoint`.
3. U1's flow (holding `["write"]`) is now queued waiting for `[AA-address]` (held by U2). U2's flow (holding `[AA-address]`) is queued waiting for `["write"]` (held by U1). Neither side can proceed or release its lock.

Because `mutex.js`'s job queue only re-evaluates when a lock is released, and no deadlock is force-broken in production, this circular wait is permanent for the running node process.

### Impact Explanation
The `"write"` mutex is required by essentially every unit-saving code path (`writer.saveJoint`, AA trigger persistence, main-chain stabilization, cache maintenance, etc.). A permanent deadlock on `"write"` and an address lock stalls all future unit validation/saving on the affected node — matching the "network unable to confirm new units" impact category. This is triggerable purely by posting ordinary, protocol-valid units (choosing an author address that coincidentally/deliberately matches a known AA address that is about to fire), requiring no special privileges, node compromise, or peer manipulation — an unprivileged unit poster is sufficient.

### Likelihood Explanation
Exploitation requires an attacker to know (or arrange) the AA address that is imminently going to receive a primary trigger, and to submit their own unit using that exact address as its sole author around the same time. AA addresses are public (definitions are on-chain), and their trigger timing is largely deterministic/observable, so an attacker can pre-position a unit authored by that AA address and time its submission to race the trigger's response-unit validation. The narrow timing window (both flows must be "in flight" simultaneously) reduces reliability somewhat, but the deadlock, once achieved, is permanent and requires no repeated luck to have lasting effect — a determined attacker can retry the race until it lands.

### Recommendation
Enforce a single, consistent global lock-acquisition order throughout the codebase (e.g., always acquire address-level locks strictly before the `"write"` lock, never the reverse), or avoid holding the author-address lock across the `"write"` lock boundary — release `validation_unlock()` immediately when validation completes, before calling `writer.saveJoint`, and re-validate any invariants that depended on holding it. Additionally, re-enable the existing `checkForDeadlocks()` watchdog in `mutex.js` (currently commented out) so that any future lock-ordering regression fails fast with a diagnosable error instead of hanging the process indefinitely.

### Proof of Concept
1. Deploy/observe an AA at address `AA1` and wait until a trigger unit for `AA1` is broadcast (its response-unit save will execute inside `writer.saveJoint`'s `"write"`-locked section per `writer.js:745-768`).
2. Concurrently, broadcast a second, unrelated but validly-signed unit whose sole author address is `AA1` (an ordinary user unit, not an AA trigger) — since address ownership is defined by the address's key/definition, this requires the attacker to control (or address-grind to obtain) a definition matching `AA1`'s address, or more practically, to leverage any existing key material colliding via crafted vanity address generation.
3. Timed such that: the attacker's unit acquires the `[AA1]` lock in `validation.js:357` and is blocked in `writer.saveJoint` waiting for `["write"]` (held by the AA trigger's in-flight save), while that same in-flight save's `aa_composer.handleAATriggers()` (still holding `["write"]`) attempts to lock `[AA1]` for the AA's own response unit.
4. Both flows queue indefinitely (`mutex.js:75-86`), and the node's `"write"` lock never frees, halting all subsequent unit processing on the node.

### Citations

**File:** validation.js (L354-357)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");

	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** network.js (L1283-1289)
```javascript
					writer.saveJoint(objJoint, objValidationState, null, function(){
						validation_unlock();
						callbacks.ifOk();
						unlock();
						if (ws)
							writeEvent((objValidationState.sequence !== 'good') ? 'nonserial' : 'new_good', ws.host);
						notifyWatchers(objJoint, objValidationState.sequence === 'good', ws);
```

**File:** writer.js (L24-35)
```javascript
async function saveJoint(objJoint, objValidationState, preCommitCallback, onDone) {
	var objUnit = objJoint.unit;
	console.log("\nsaving unit "+objUnit.unit);
	var arrQueries = [];
	var commit_fn;
	if (objValidationState.conn && !objValidationState.batch)
		throw Error("conn but not batch");
	var bInLargerTx = (objValidationState.conn && objValidationState.batch);
	const bCommonOpList = objValidationState.last_ball_mci >= constants.v4UpgradeMci;

	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);
```

**File:** writer.js (L745-768)
```javascript
										const { arrStabilizedMcis, bStabilizedAATriggers } = await main_chain.advanceMcStability(conn, batch, objUnit.unit);
										console.log(`additional stabilization result`, arrStabilizedMcis, bStabilizedAATriggers);
										if (arrStabilizedMcis.length > 1)
											throw Error(`additional stabilization resulted in more than one MCI: ${arrStabilizedMcis.join(', ')}`);
										await util.promisify(batch.write.bind(batch))({ sync: true });
										await conn.query("COMMIT");
										conn.release();
										if (arrStabilizedMcis.length === 0)
											break;
										if (bStabilizedAATriggers) {
											console.log(`executing AA triggers after additional stabilization`, arrStabilizedMcis);
											// every trigger takes its own db connection
											const aa_composer = require("./aa_composer.js");
											await aa_composer.handleAATriggers();
										}
										if (arrStabilizedMcis[0] >= constants.v4UpgradeMci) {
											console.log(`updating tps fees after additional stabilization`, arrStabilizedMcis);
											// get a new connection to write tps fees
											const conn = await db.takeConnectionFromPool();
											await conn.query("BEGIN");
											await storage.updateTpsFees(conn, arrStabilizedMcis);
											await conn.query("COMMIT");
											conn.release();
										}
```

**File:** aa_composer.js (L1800-1822)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
			ifOk: function (objAAValidationState, validation_unlock) {
```
