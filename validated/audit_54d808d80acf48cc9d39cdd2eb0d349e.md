### Title
Premature release of the author-address validation lock in AA unit processing before writer.saveJoint commits — race enabling stale-state double validation of AA balances (File: `aa_composer.js`)

### Summary
`validation.validate()` in `validation.js` serializes per-author-address validation using `mutex.lock(arrAuthorAddresses, ...)` and hands the caller an `unlock` function (`validation_unlock`) that is meant to be held until the corresponding write is actually persisted. This mirrors the Linux `po->bind_lock` pattern in the reported CVE, where a lock protecting a multi-step operation is dropped mid-way, letting a second actor observe/act on inconsistent intermediate state. In `aa_composer.js`'s `validateAndSaveUnit()`, `validation_unlock()` is invoked immediately inside `ifOk`, **before** `writer.saveJoint()` is even called, unlike every other caller of `validation.validate()` in the codebase. [1](#0-0) 

### Finding Description
`validation.js` takes the author-address lock for the entire duration of validation and only passes the `unlock` callback to `ifOk`, expecting the caller to keep the address serialized until the unit's effects are durably written: [2](#0-1) [3](#0-2) 

Every "normal" caller respects this contract and defers `validation_unlock()` until inside `writer.saveJoint`'s completion callback, i.e., after the unit (and its spends) are actually persisted:
- `network.js` `handleJoint`: unlock happens inside `writer.saveJoint(...)`'s `onDone`. [4](#0-3) 
- `divisible_asset.js` and `indivisible_asset.js` getSavingCallbacks: unlock happens inside `writer.saveJoint`'s `onDone`, not before. [5](#0-4) [6](#0-5) 

In contrast, `aa_composer.js`'s `validateAndSaveUnit()` calls `validation_unlock()` **immediately** after validation succeeds and only then calls `writer.saveJoint()`: [7](#0-6) 

This releases the per-address serialization lock (`arrAuthorAddresses`, which for an AA-generated unit is the AA's own address) while the unit's balance/state changes are still uncommitted (the surrounding AA execution uses a batch/transaction and an in-flight `conn`, only actually finalized later by `writer.saveJoint` and the outer trigger-handling commit). `writer.saveJoint` is only prevented from re-acquiring the global "write" mutex because `objAAValidationState.bUnderWriteLock` is set to `true`, which itself proves the surrounding AA-trigger flow assumes it already holds the "write" lock — but `validation.validate()`'s address-specific lock is a *different*, narrower lock that is dropped early regardless of the "write" lock's state.

Because `validation.validate()` for any other unit addressed to (authored by) the same AA can now acquire the freed `arrAuthorAddresses` lock and run its own read-based validation (balance/output checks) concurrently with the first trigger's not-yet-committed writes, it can observe stale/pre-spend balance state. The second validation will pass with a stale view, then queue on the global "write" lock waiting for the first `saveJoint` to finish; once it fires, it proceeds to save with a stale precondition, producing double use of the same AA fund/output — the same class of "unlock before operation truly completes, second actor races in" bug described in the kernel CVE for `packet_set_ring()`/`packet_notifier()`.

### Impact Explanation
If two AA trigger executions/response units for the same AA address can be validated concurrently across this window, an attacker who can trigger the same AA rapidly from concurrent primary units (a capability available to any unprivileged unit poster who can construct triggers against a target AA) could cause the AA to double-count available balance, leading to AA fund loss (unauthorized spending of the AA's balance) or state corruption between nodes that race differently, potentially causing node disagreement about the AA's resulting balance/state — both are impacts explicitly in scope.

### Likelihood Explanation
Likelihood is limited by how AA-trigger processing is scheduled at a higher level (e.g., whether the surrounding main-chain stabilization code strictly serializes trigger execution across different primary units targeting the same AA before dispatching secondary/`validateAndSaveUnit` calls). I was not able to fully trace this outer scheduler within the available tool budget (searches for `handleAATriggers`/trigger dispatch loop callers did not resolve conclusively), so I cannot confirm with certainty that concurrent `validateAndSaveUnit` calls for the same AA address are reachable in practice, only that the lock-release-timing bug is real and structurally analogous to the reported CVE, and it is inconsistent with the safe pattern used by every other `validation.validate()` caller in the codebase.

### Recommendation
In `aa_composer.js`'s `validateAndSaveUnit()`, move the call to `validation_unlock()` out of the immediate `ifOk` handler and into the completion callback of `writer.saveJoint()`, mirroring the pattern already used in `network.js`, `divisible_asset.js`, and `indivisible_asset.js`, so the author-address lock is held for the entire duration of validation-plus-write, not released prematurely.

### Proof of Concept
Not independently reproducible from static analysis alone given the uncertainty about the outer AA-trigger scheduling/serialization noted above; a concrete PoC would require instrumenting concurrent trigger dispatch to the same AA address and observing whether a second trigger's `validation.validate()` call is able to acquire the `arrAuthorAddresses` lock and read pre-write balance state while the first trigger's `writer.saveJoint()` call for that AA is still pending — this would need to be verified by a Devin session with runtime access, not from the indexed code alone.

### Citations

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

**File:** validation.js (L357-357)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** validation.js (L484-490)
```javascript
						if (objJoint.unsigned){
							unlock();
							callbacks.ifOkUnsigned(objValidationState.sequence === 'good');
						}
						else
							callbacks.ifOk(objValidationState, unlock);
					});
```

**File:** network.js (L1283-1288)
```javascript
					writer.saveJoint(objJoint, objValidationState, null, function(){
						validation_unlock();
						callbacks.ifOk();
						unlock();
						if (ws)
							writeEvent((objValidationState.sequence !== 'good') ? 'nonserial' : 'new_good', ws.host);
```

**File:** divisible_asset.js (L395-406)
```javascript
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

**File:** indivisible_asset.js (L947-961)
```javascript
					var saveAndUnlock = function(){
						writer.saveJoint(
							objJoint, objValidationState, 
							preCommitCallback,
							function onDone(err){
								console.log("saved unit "+unit+", err="+err);
								validation_unlock();
								combined_unlock();
								if (bPreCommitCallbackFailed)
									callbacks.ifError("precommit callback failed: "+err);
								else
									callbacks.ifOk(objJoint, arrRecipientChains, arrCosignerChains);
							}
						);
					};
```
