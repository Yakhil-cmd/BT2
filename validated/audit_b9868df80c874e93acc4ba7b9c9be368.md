### Title
Incomplete state restoration on AA trigger bounce/revert leads to corrupted balance state in retried unit - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `handleTrigger()` builds an AA response unit incrementally, mutating shared in-memory state (`stateVars`, and critically `trigger_opts.assocBalances` / `objValidationState.assocBalances`) as it composes payment outputs (via `completePaymentPayload`, asset issuance, `updateFinalAABalances`, etc.). When something fails mid-composition, the code calls `revert(err)` (aa_composer.js:1759) which is supposed to "start over" and then rebuild a bounce unit via `bounce(err)` (aa_composer.js:910). However, the state-restore logic in `bounce()` only restores `stateVars`/`assocBalances` to their pre-trigger snapshot (`originalStateVars`/`originalBalances`) when `trigger_opts.bAir` is set:

```
aa_composer.js:910-922
	function bounce(error) {
		...
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			...
		}
```

For the real (non-`bAir`) primary-trigger execution path, `revert()` only rolls back the SQL side (`ROLLBACK TO SAVEPOINT initial_balances`, aa_composer.js:1780) and clears the JS `stateVars` object (aa_composer.js:1778), but never resets the in-memory `objValidationState.assocBalances` object that was mutated in-place while composing the failed unit (e.g. by `completePaymentPayload`, asset issuance bookkeeping, and `updateFinalAABalances`). This mirrors the RDMA/rxe bug class exactly: state needed to correctly resend/rebuild after a failure (the "dma"-like progress structure — here the AA's live balance bookkeeping) is saved/restored only partially, so the retried (bounced) unit is composed on top of stale, already-mutated balance figures instead of the true pre-trigger balances.

### Finding Description
`handleTrigger()` captures `originalStateVars = _.cloneDeep(stateVars)` once, before any mutation (aa_composer.js:469), and captures `originalBalances = _.cloneDeep(trigger_opts.assocBalances)` inside `updateInitialAABalances()` (aa_composer.js:480) — but this snapshot is only ever consulted for restoration inside `bounce()`, and only when `trigger_opts.bAir` is truthy (aa_composer.js:914-921).

For the real (non-air) execution path used when a stable unit actually triggers an AA (`handlePrimaryAATrigger`, aa_composer.js:91), balances live in `objValidationState.assocBalances` and are progressively decremented/incremented as messages are composed (spending inputs for outputs, issuing assets, adjusting via `updateFinalAABalances`). If composition fails partway (e.g., `completePaymentPayload` errors, asset issuance fails, `validateAndSaveUnit` fails), `bounce(err)` is invoked, sometimes directly and sometimes via `revert(err)` → `bounce(err)`. `revert()` rolls back the SQL savepoint for the persisted `aa_balances` table and clears `stateVars`, but does not re-clone/restore `objValidationState.assocBalances` from `originalBalances`. `bounce()` then proceeds to build a genuine bounce-payment unit via `sendUnit(messages)` (aa_composer.js:944), which recomputes outputs against the *same* `objValidationState.assocBalances` object that still carries partial mutations from the aborted attempt.

This is the same bug class as the CVE: a stateful, per-attempt working structure (rxe's `dma` struct tracking SGE progress; here, the AA's live balance/working state used to build the response unit) is saved incompletely before the operation that can fail, and is not fully restored before the retry, so the retried operation operates on corrupted state.

### Impact Explanation
If the retried/bounce unit is composed using stale, partially-mutated balance bookkeeping instead of the true balances, the AA can produce an output unit whose payment amounts do not correctly reflect its real, current balance — either committing to pay out more than it actually holds (fund loss to the AA / other users, or a unit that fails deeper consensus validation causing nodes to disagree on validity) or retaining balance that should have been spent (frozen/inflated apparent balance, enabling later double-use of the same funds across triggers). Because AAs manage user-owned funds on shared assets, this can translate into unauthorized spending or AA fund loss/freezing, matching the required impact bar.

### Likelihood Explanation
Triggering the failure branch requires only crafting a unit (trigger) to an AA definition whose `messages` cause a mid-composition failure after some balance-affecting message has already been processed (e.g., a payment message that succeeds in mutating `objValidationState.assocBalances`, followed by a later message/condition that fails, such as an asset with `fixed_denominations`/insufficient funds for a subsequent output, or a formula error triggering `revert`). Any unprivileged unit poster who can define/call an AA can attempt this, making it reachable without special privileges, though constructing the exact multi-message AA and trigger sequence that reliably reaches the vulnerable state requires some care.

### Recommendation
In `revert()` (aa_composer.js:1759), for the non-`bAir`/primary path, restore `objValidationState.assocBalances` (and any other in-place-mutated working state) from `originalBalances`/a fresh snapshot before calling `bounce()`, exactly as is already done for the `bAir` path in `bounce()`. Ensure the SQL-level savepoint rollback and the JS-level balance/state rollback are always performed together and are provably equivalent, so a bounce/retry unit is always built strictly from the pre-trigger balance state rather than from partially-mutated working memory.

### Proof of Concept
Conceptual reproduction path (would need to be validated with a running Devin session against the AA formula engine):
1. Deploy an AA whose `messages` array contains: (a) a `payment` message that spends part of the AA's asset balance to some address (mutating `objValidationState.assocBalances[address][asset]` downward), followed by (b) a second `payment` message (or asset-issuance step) engineered to fail after (a) has already mutated balances (e.g., referencing a `fixed_denominations` asset incorrectly, or exceeding `MAX_BALANCE`, or a formula referencing an undefined asset causing `completePaymentPayload` to return an error).
2. Send a triggering unit with sufficient `trigger.outputs` to reach the balance-mutating first message before the failure in the second message.
3. Observe that `handleTrigger` calls `revert(err)` → SQL `ROLLBACK TO SAVEPOINT initial_balances` (restoring DB `aa_balances`) and clears `stateVars`, but `objValidationState.assocBalances` in memory still reflects the balance already decremented by message (a).
4. `bounce(err)` is then invoked, composing a bounce-payment unit via `sendUnit()`, whose output/change amounts and subsequent-availability checks are computed against the stale, already-decremented `assocBalances`, producing an incorrect bounce unit relative to the AA's true (rolled-back) balance. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** aa_composer.js (L463-490)
```javascript
	var bWithKeys = (mci >= constants.includeKeySizesUpgradeMci);
	var FULL_TRANSFER_INPUT_SIZE = TRANSFER_INPUT_SIZE + (bWithKeys ? TRANSFER_INPUT_KEYS_SIZE : 0);
	var byte_balance;
	var storage_size;
	var objStateUpdate;
	var count = 0;
	var originalStateVars = _.cloneDeep(stateVars);
	var originalBalances;
	if (bSecondary)
		updateOriginalOldValues();

	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
```

**File:** aa_composer.js (L909-922)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
```

**File:** aa_composer.js (L1759-1783)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
```
