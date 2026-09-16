### Title
Double-spend acceptance for private assets writes `is_unique=NULL` under a `private_write` lock that does not synchronize with the `write` lock used for unit persistence, allowing a lost-update / TOCTOU race on the `inputs` table - ([File: validation.js])

### Summary
The reported kernel bug is a classic "two different lock domains protect the same shared object" race: `perf_event_set_output()` takes `e1->mmap_mutex` while `perf_mmap_close()` takes `e2->mmap_mutex`, so a shared `rb` object gets mutated from two paths that don't exclude each other. ocore has an analogous pattern in the double-spend-acceptance logic for private assets: the in-place mutation of the `inputs` table (`is_unique=NULL`) that "un-uniques" a conflicting record is protected only by a narrow, short-lived `private_write` mutex key, while the authoritative unit-persistence path (`writer.saveJoint`) that inserts/updates the very same `inputs` rows is protected by a different key, `write`. These two disjoint lock domains never mutually exclude each other.

### Finding Description
In `validatePaymentInputsAndOutputs`'s `checkInputDoubleSpend` → `acceptDoublespends` callback, when the current unit's asset is private, the code performs an immediate, synchronous UPDATE on the `inputs` table to un-mark a conflicting record as unique: [1](#0-0) 

This UPDATE is guarded only by `mutex.lock(["private_write"], ...)`: [2](#0-1) 

For non-private assets, the equivalent mutation is instead deferred and pushed into `objValidationState.arrAdditionalQueries`, to be executed later as part of `writer.saveJoint`'s single atomic write transaction: [3](#0-2) 

However, `writer.saveJoint`, which performs the actual `INSERT INTO inputs` / `UPDATE outputs SET is_spent=1` operations that create and mutate the same `inputs`/`outputs` rows, acquires a completely different mutex key, `"write"`, not `"private_write"`: [4](#0-3) [5](#0-4) 

Because `mutex.lock` only serializes callers that request overlapping keys (see `isAnyOfKeysLocked`/`exec` in `mutex.js`), a unit being validated (holding only `arrAuthorAddresses` lock from `validation.validate`, plus a transient `private_write` lock for the immediate UPDATE) is not mutually excluded from another unit concurrently being written by `writer.saveJoint` (holding the `write` lock) that touches the exact same `inputs` row (e.g., the losing side of the double-spend, or a private chain being saved by `indivisible_asset.js`/`divisible_asset.js`'s `getSavingCallbacks`, which insert/overwrite via `INSERT ... IGNORE` and `UPDATE outputs SET ... WHERE is_spent=0`): [6](#0-5) 

This is structurally identical to the kernel race: two code paths mutate the same shared resource (`e2->rb->event_list` in the kernel; the `inputs`/`outputs` rows for the conflicting private-asset spend in ocore) while holding two different, non-overlapping locks (`e1->mmap_mutex`/`e2->mmap_mutex` in the kernel; `private_write`/`write` in ocore), so no actual mutual exclusion exists between them.

### Impact Explanation
If the immediate `UPDATE inputs SET is_unique=NULL ...` (protected by `private_write`) interleaves with a concurrent `writer.saveJoint` transaction (protected by `write`) that is simultaneously inserting new `inputs`/updating `outputs.is_spent` for a competing spend of the same private-asset output, the two operations can race on the same rows outside of a single serializing transaction boundary. Depending on DB isolation and statement ordering, this can leave the `is_unique` marking of `inputs` rows inconsistent with what `checkForDoublespends`/`readNextSpendableMcIndex` logic assumes, i.e., two conflicting spends of a private-asset output could both remain "unique" (both accepted as good/serial), or the sequence-resolution `is_unique=NULL` unmarking could be silently lost/overwritten by a concurrent write. In a private (hidden) asset chain, this can permit acceptance of two spends for the same underlying output as long as they later independently reach different nodes — a supply/double-spend inconsistency of privately transferred asset balance, which is a fund-loss/double-spend class impact.

### Likelihood Explanation
This path is reachable by an ordinary asset issuer/holder: any user can create a private (indivisible or divisible) asset, and any counterparty of a private payment can construct two conflicting spends of the same private output and get them validated by two different local nodes/instances close together in time. Triggering the race requires two units competing for the same private-asset output to be validated concurrently, which is exactly the double-spend scenario ocore's `checkForDoublespends`/`acceptDoublespends` mechanism is designed to reconcile — meaning the race window is entered specifically in the double-spend-handling code path, which is a routine occurrence for private-asset transfers (not a rare edge case), making it a realistic Medium-likelihood race given ocore's fully async/callback-driven concurrency model.

### Recommendation
Use the same lock key for the immediate in-place `inputs.is_unique` mutation as is used for the authoritative unit-write path (`"write"`), or fold the private-asset "un-unique" UPDATE into `objValidationState.arrAdditionalQueries` so it executes atomically within the same `writer.saveJoint` transaction under the `write` lock, exactly as done for non-private assets. Alternatively, have `checkInputDoubleSpend`'s private-asset branch also acquire the `write` lock (in addition to/instead of `private_write`) before touching `inputs`, ensuring mutual exclusion with `writer.saveJoint`.

### Proof of Concept
Conceptual PoC (cannot be executed without full node infrastructure, but the logical race is directly derivable from the cited code):
1. Issue a private (hidden) asset via `indivisible_asset.js`/`divisible_asset.js` and privately transfer an output `O` to Wallet A and (as a parallel unit) construct a conflicting spend of the same underlying source output to Wallet B, using two independent node instances or two rapid submissions to the same node before either is persisted.
2. Node processes unit U1 (spending `O`): `validatePaymentInputsAndOutputs` reaches `checkInputDoubleSpend`, finds the pre-existing conflicting `inputs` row from another still-unstable unit U2, and since the asset `is_private`, takes `mutex.lock(["private_write"])` and issues `UPDATE inputs SET is_unique=NULL ...` directly against the DB — outside of the `write` lock scope. [2](#0-1) 
3. Concurrently, `writer.saveJoint` is committing unit U2 (or a third unit spending the same private output) under the `write` lock, performing its own `INSERT INTO inputs` / `UPDATE outputs SET is_spent=1` for the same logical output. [5](#0-4) 
4. Because `private_write` and `write` are disjoint mutex keys, `mutex.js`'s `isAnyOfKeysLocked` does not detect the overlap, so both operations proceed concurrently against overlapping `inputs`/`outputs` rows, producing a state where the double-spend resolution (`is_unique=NULL`) can be lost or applied against a row already superseded by the concurrent commit — leaving both conflicting private-asset spends recorded as valid/unique in different local views.

Note: Because ocore's actual runtime interleaving depends on the underlying DB driver's callback scheduling (sqlite vs mysql) and precise timing, I was not able to fully verify from static code alone whether the specific SQL engine used serializes these two statements via the DB layer itself (e.g., single-connection sqlite session) in all deployment configurations; this uncertainty affects the practical exploitability window and would need dynamic testing to confirm the race can actually manifest across the sqlite/mysql code paths ocore supports.

### Citations

**File:** validation.js (L2274-2296)
```javascript
					function acceptDoublespends(cb3){
						console.log("--- accepting doublespend on unit "+objUnit.unit);
						var sql = "UPDATE inputs SET is_unique=NULL WHERE "+doubleSpendWhere+
							" AND (SELECT is_stable FROM units WHERE units.unit=inputs.unit)=0";
						if (!(objAsset && objAsset.is_private)){
							objValidationState.arrAdditionalQueries.push({sql: sql, params: doubleSpendVars});
							objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
							return cb3();
						}
						mutex.lock(["private_write"], function(unlock){
							console.log("--- will ununique the conflicts of unit "+objUnit.unit);
							conn.query(
								sql, 
								doubleSpendVars, 
								function(){
									console.log("--- ununique done unit "+objUnit.unit);
									objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
									unlock();
									cb3();
								}
							);
						});
					}, 
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

**File:** writer.js (L367-383)
```javascript
								conn.addQuery(arrQueries, "INSERT INTO inputs \n\
										(unit, message_index, input_index, type, \n\
										src_unit, src_message_index, src_output_index, \
										from_main_chain_index, to_main_chain_index, \n\
										denomination, amount, serial_number, \n\
										asset, is_unique, address) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
									[objUnit.unit, i, j, type, 
									 src_unit, src_message_index, src_output_index, 
									 from_main_chain_index, to_main_chain_index, 
									 denomination, input.amount, input.serial_number, 
									 payload.asset, is_unique, address]);
								switch (type){
									case "transfer":
										conn.addQuery(arrQueries, 
											"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
											[src_unit, src_message_index, src_output_index]);
										break;
```

**File:** indivisible_asset.js (L252-288)
```javascript
				if (!input.type) // transfer
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, src_unit, src_message_index, src_output_index, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,?,'transfer',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.unit, input.message_index, input.output_index, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else if (input.type === 'issue')
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, serial_number, amount, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,'issue',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.serial_number, input.amount, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else
					throw Error("neither transfer nor issue after validation");
				var is_serial = objPrivateElement.bStable ? 1 : null; // initPrivatePaymentValidationState already checks for non-serial
				var outputs = payload.outputs;
				for (var output_index=0; output_index<outputs.length; output_index++){
					var output = outputs[output_index];
					console.log("inserting output "+JSON.stringify(output));
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO outputs \n\
						(unit, message_index, output_index, amount, output_hash, asset, denomination) \n\
						VALUES (?,?,?,?,?,?,?)",
						[objPrivateElement.unit, objPrivateElement.message_index, output_index, 
						output.amount, output.output_hash, payload.asset, payload.denomination]);
					var fields = "is_serial=?";
					var params = [is_serial];
					if (output_index === objPrivateElement.output_index){
						var is_spent = (i===0) ? 0 : 1;
						fields += ", is_spent=?, address=?, blinding=?";
						params.push(is_spent, objPrivateElement.output.address, objPrivateElement.output.blinding);
					}
					params.push(objPrivateElement.unit, objPrivateElement.message_index, output_index);
					conn.addQuery(arrQueries, "UPDATE outputs SET "+fields+" WHERE unit=? AND message_index=? AND output_index=? AND is_spent=0", params);
				}
```
