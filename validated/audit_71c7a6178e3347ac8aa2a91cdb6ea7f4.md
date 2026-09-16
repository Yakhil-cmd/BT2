### Title
Race condition from premature address-mutex release during AA unit validation/save allows concurrent state corruption at the same AA address - (File: aa_composer.js)

### Summary
`validateAndSaveUnit()` in `aa_composer.js` releases the per-address validation mutex (`validation_unlock()`) *before* the unit's write (`writer.saveJoint`) has completed, unlike every other caller of `validation.validate()` in the codebase (`network.js`, `divisible_asset.js`, `indivisible_asset.js`), which all defer the unlock until *after* `writer.saveJoint()`'s callback fires.

### Finding Description
`validation.validate()` acquires a mutex keyed on the unit's author addresses (`mutex.lock(arrAuthorAddresses, ...)` in `validation.js`) and only hands the caller the `unlock` function inside `ifOk`, with the explicit contract that the caller must hold this lock until the corresponding write is durably applied — this is exactly how `network.js`'s `handleJoint` (`ifOk: async function(objValidationState, validation_unlock){ ... writer.saveJoint(objJoint, objValidationState, null, function(){ validation_unlock(); ... }); }` [1](#0-0) ), `divisible_asset.js`'s `getSavingCallbacks` [2](#0-1) , and `indivisible_asset.js`'s `getSavingCallbacks` [3](#0-2)  all behave — they call `validation_unlock()` only from inside the `writer.saveJoint` completion callback.

In `aa_composer.js`, `validateAndSaveUnit()` instead calls `validation_unlock()` immediately upon entering `ifOk`, before `writer.saveJoint()` is even invoked: [4](#0-3) 

This is the mirror of the CVE-2021-39686 bug class: the checked/validated state (the address's mutex-protected view during `validate()`) is released before the corresponding action (the actual persistence of that validated state via `writer.saveJoint`) is completed, creating a window in which the security-relevant serialization guarantee no longer matches the real state of the system. In `binder.c`, releasing the security-context reference before the transaction it protects completes let SELinux make an authorization decision against a stale/wrong domain; here, releasing the per-address mutex before `writer.saveJoint()` finishes lets a second validation for the *same AA address* (e.g. from a concurrently processed secondary/recursive AA trigger to the same address, or another primary trigger targeting the same AA in parallel — `handleAATriggers`/`handleTrigger` process multiple independent trigger units and can invoke `validateAndSaveUnit` from different execution contexts) begin and pass `validation.validate()`'s serial/double-spend/definition checks against a database view that does not yet reflect the balance changes, output creations, or state-variable updates the just-"unlocked" unit is still in the process of writing.

### Impact Explanation
Because the address mutex is the mechanism that serializes concurrent validation for a given address specifically to prevent races over balances, sequence, and address definition, releasing it early defeats that guarantee for AA-address units. A second trigger/response processed for the same AA address inside the gap between `validation_unlock()` and the completion of `writer.saveJoint()` could be validated against pre-write state, opening the door to double-spending the AA's own balance, inconsistent bookkeeping between the AA's tracked balances and what is committed, or divergent node views of validity/sequence for AA-address outputs — i.e., unauthorized spending of AA funds, AA fund loss/freezing, or node disagreement on validity, matching the accepted impact classes.

### Likelihood Explanation
Exploitation requires only that two events targeting the same AA address are processed within the small window between `validation_unlock()` and `writer.saveJoint()`'s completion — achievable by an ordinary unprivileged user who triggers overlapping recursive/secondary AA calls or repeated primary triggers to the same AA address, both of which are attacker-controllable inputs (a posted trigger unit, or the AA's own logic issuing secondary triggers). No special privileges, malicious peers, or network manipulation are needed; only careful timing/ordering of legitimate trigger submissions.

### Recommendation
Move the `validation_unlock()` call in `aa_composer.js`'s `validateAndSaveUnit()` so it executes only after `writer.saveJoint()`'s completion callback, matching the pattern used in `network.js`, `divisible_asset.js`, and `indivisible_asset.js`. This preserves the address-level serialization invariant for the full validate-then-persist critical section.

### Proof of Concept
1. Deploy/trigger an AA (address `A`) such that processing one primary trigger causes it to also schedule a secondary trigger back to `A` (or arrange two independent primary triggers to `A` to be posted back-to-back so their processing overlaps in the node's event loop).
2. When the first trigger's `validateAndSaveUnit()` reaches `ifOk`, `validation_unlock()` fires immediately (`aa_composer.js:1825`), releasing the mutex on address `A` while `writer.saveJoint()` (which updates AA balances/outputs for `A`) is still executing asynchronously.
3. Because the mutex for `A` is now free, a second trigger/response targeting `A` can enter `validation.validate()` and complete its checks (balance/sequence/definition reads) before the first unit's `writer.saveJoint()` has committed its changes, causing the second unit's validation results to be based on stale state.
4. Depending on timing, this can result in the AA effectively double-counting or double-spending its available balance across the two concurrently processed units, or leaving nodes that process the pair in a different relative order to disagree on final AA state — reproducible by instrumenting `validateAndSaveUnit` to log/delay between `validation_unlock()` and `writer.saveJoint()` and firing two same-address triggers within that delay.

### Citations

**File:** network.js (L1258-1288)
```javascript
				ifOk: async function(objValidationState, validation_unlock){
					clearHost();
					if (objJoint.unsigned)
						throw Error("ifOk() unsigned");
					if (bPosted && objValidationState.sequence !== 'good') {
						validation_unlock();
						callbacks.ifUnitError("The transaction would be non-serial (a double spend)");
						delete assocUnitsInWork[unit];
						unlock();
						if (ws)
							writeEvent('nonserial', ws.host);
						return;
					}
					if (conf.bDryRunNewTriggers && !conf.bLight && !objJoint.ball && objValidationState.count_primary_aa_triggers) {
						const outputAddresses = objJoint.unit.messages
							.filter(msg => msg.app === 'payment')
							.reduce((acc, msg) => acc.concat(msg.payload.outputs.map(output => output.address)), []);
						const rows = await db.query("SELECT address, definition FROM aa_addresses WHERE address IN (?)", [outputAddresses]);
						for (let { address, definition } of rows) {
							console.log(`dry run trigger for AA address ${address} in submitted unit ${unit}`);
							const trigger = aa_composer.getTrigger(objJoint.unit, address);
							// if it would crash, let it crash now, not when we execute the trigger for real
							await aa_composer.dryRunPrimaryAATrigger(trigger, address, JSON.parse(definition));
						}
					}
					writer.saveJoint(objJoint, objValidationState, null, function(){
						validation_unlock();
						callbacks.ifOk();
						unlock();
						if (ws)
							writeEvent((objValidationState.sequence !== 'good') ? 'nonserial' : 'new_good', ws.host);
```

**File:** divisible_asset.js (L343-406)
```javascript
				ifOk: function(objValidationState, validation_unlock){
					console.log("divisible asset OK "+objValidationState.sequence);
					if (objValidationState.sequence !== 'good'){
						validation_unlock();
						combined_unlock();
						return callbacks.ifError("Divisible asset bad sequence "+objValidationState.sequence);
					}
					var bPrivate = !!assocPrivatePayloads;
					var arrPrivateElements = [];
					var preCommitCallback = null;
					
					if (bPrivate){
						preCommitCallback = function(conn, cb){
							async.eachSeries(
								Object.keys(assocPrivatePayloads),
								function(payload_hash, cb2){
									var payload = assocPrivatePayloads[payload_hash];
									var message_index = composer.getMessageIndexByPayloadHash(objUnit, payload_hash);
									var objPrivateElement = {
										unit: unit,
										message_index: message_index,
										payload: payload
									};
									validateAndSaveDivisiblePrivatePayment(conn, objPrivateElement, {
										ifError: function(err){
											cb2(err);
										},
										ifOk: function(){
											arrPrivateElements.push(objPrivateElement);
											cb2();
										}
									});
								},
								cb
							);
						};
					} else {
						if (typeof callbacks.preCommitCb === "function") {
							preCommitCallback = function(conn, cb){
								callbacks.preCommitCb(conn, objJoint, cb);
							}
						}
					}
					
					composer.postJointToLightVendorIfNecessaryAndSave(
						objJoint, 
						function onLightError(err){ // light only
							console.log("failed to post divisible payment "+unit);
							validation_unlock();
							combined_unlock();
							callbacks.ifError(err);
						},
						function save(){
							writer.saveJoint(
								objJoint, objValidationState, 
								preCommitCallback,
								function onDone(err){
									console.log("saved unit "+unit+", err="+err, arrPrivateElements);
									validation_unlock();
									combined_unlock();
									var arrChains = arrPrivateElements.length ? arrPrivateElements.map(function(objPrivateElement){ return [objPrivateElement]; }) : null; // each chain consists of one element
									callbacks.ifOk(objJoint, arrChains, arrChains);
								}
							);
```

**File:** indivisible_asset.js (L856-866)
```javascript
				ifOk: function(objValidationState, validation_unlock){
					console.log("Private OK "+objValidationState.sequence);
					if (objValidationState.sequence !== 'good'){
						validation_unlock();
						combined_unlock();
						return callbacks.ifError("Indivisible asset bad sequence "+objValidationState.sequence);
					}
					var bPrivate = !!assocPrivatePayloads;
					var arrRecipientChains = bPrivate ? [] : null; // chains for to_address
					var arrCosignerChains = bPrivate ? [] : null; // chains for all output addresses, including change, to be shared with cosigners (if any)
					var preCommitCallback = null;
```

**File:** aa_composer.js (L1822-1836)
```javascript
			ifOk: function (objAAValidationState, validation_unlock) {
				if (objAAValidationState.sequence !== 'good')
					throw Error("nonserial AA");
				validation_unlock();
				objAAValidationState.bUnderWriteLock = true;
				objAAValidationState.conn = conn;
				objAAValidationState.batch = batch;
				objAAValidationState.initial_trigger_mci = mci;
				objAAValidationState.bDryRun = trigger_opts.bDryRun;
				writer.saveJoint(objJoint, objAAValidationState, null, function(err){
					if (err)
						throw Error('AA writer returned error: ' + err);
					cb();
				});
			}
```
