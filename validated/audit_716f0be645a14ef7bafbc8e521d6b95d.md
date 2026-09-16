### Title
AA state variables (e.g. merkle roots used for reward/airdrop claims) can be overwritten before a pending claim trigger executes, causing the claimer's funds to be lost — ([File: formula/evaluation.js], [File: aa_composer.js])

### Summary
Autonomous Agents (AAs) commonly implement "claim from a fixed distribution" logic (merkle-root-based airdrops, vesting, bribe distribution, etc.) by storing a current merkle root (or other claim metadata) in a mutable AA state variable and verifying inbound claim triggers with `is_valid_merkle_proof`. Because AA state variables are stored as a single overwritable key with no history, and AA triggers execute only once their unit is stable on the DAG (not in the order they were authored), an update to that state variable performed by the AA owner/updater between the time a user composes/broadcasts a claim trigger and the time that trigger actually stabilizes and executes can invalidate the user's proof, causing the claim to bounce and the user's attached bytes/asset to be lost or frozen (minus bounce fees), exactly analogous to the `updateRewardsMetadata` root-overwrite bug in the referenced report.

### Finding Description
State variables in AAs are persisted with a single, fully-overwritable key per `(address, var_name)`: [1](#0-0) 

Each `var[...] = ...` assignment in oscript (`state_var_assignment`) simply replaces the in-memory `stateVars[address][var_name].value`, which is later persisted verbatim, with no retained history of prior values that a claimer might have relied on: [2](#0-1) 

`is_valid_merkle_proof` only verifies that a proof/element pair are internally consistent and returns the computed root; it does not itself pin the check to a specific historical root — AA authors compare the computed root against the *current* value of a state variable such as `var['root']` to decide whether a claim is legitimate: [3](#0-2) 

Crucially, AA triggers do not execute in the order they are authored/broadcast by users — they execute only after their triggering unit becomes stable on the DAG, and are processed via `handlePrimaryAATrigger`/`handleAATriggers` once stability is reached: [4](#0-3) 

This means a user who composes a claim trigger based on the merkle root currently visible in `var['root']` has no guarantee that their trigger will stabilize and execute before the AA owner (or any other permitted updater) posts a new trigger that overwrites `var['root']` with a new value. If the owner's update stabilizes first, the user's already-broadcast (and possibly already bounce-fee-paying) claim trigger will be evaluated against the new root, the merkle proof will fail the `var['root']` comparison, and the AA will bounce the trigger — the user permanently loses the ability to claim under the old root (their proof was only valid for the old, now-overwritten value) and loses their bounce fee.

This is a direct structural analog of [M-18]: `updateRewardsMetadata` overwrote `_distributions[i].proof`/merkleRoot before a legitimate claimer submitted their claim, causing loss of an already-earned reward. In ocore, the equivalent "second call" is any subsequent state-var-updating trigger (e.g., from an admin/oracle role in the AA's own design) landing on the DAG before the claimer's trigger stabilizes.

### Impact Explanation
Any AA that manages time-bound claims (bribe/reward distribution, airdrops, vesting release lists) keyed off a single, overwritable state variable is exposed to fund loss for legitimate claimants whenever the distributor rotates/corrects the root or metadata while claims are outstanding — this is "AA fund loss/freezing" as defined in scope. Given AAs are a core, widely used ocore primitive and merkle-based claim patterns are a standard idiom (`is_valid_merkle_proof` + `var[...]`), this is a broadly reachable class of loss for any unprivileged claim-trigger sender interacting with such an AA.

### Likelihood Explanation
Likelihood is moderate-to-high in practice: DAG stabilization is not instantaneous, and any AA owner who needs to correct/rotate a root (e.g., to fix an error or add late participants, exactly the legitimate scenario disputed-but-accepted in the original report) can trivially do so while claim triggers are in flight, without any malicious intent required. Because trigger execution order depends on DAG stabilization rather than submission time, race windows are unavoidable for any AA design that follows this idiom.

### Recommendation
AA authors should avoid single-slot overwritable state for anything used to authorize a claim; instead:
- Version claim metadata (e.g., `var['root_' || version]`) and accept proofs against any still-valid version until it is explicitly retired only after a grace period with no pending claims, or
- Track claimed status per-user in immutable, append-only state (`var[user]='claimed']`) so that once a claim executes against a previously valid root it cannot be replayed, and structure root rotations as additive (new roots cover only new entries, old roots remain valid indefinitely) rather than destructive overwrites, or
- Require the update trigger itself to verify no claims are pending / allow a bounded "old-root grace window" during which both old and new root proofs are accepted.
At the protocol/documentation level, ocore should document this TOCTOU class explicitly for AA developers who base authorization logic on `var[...]` values compared against externally supplied proofs (`is_valid_merkle_proof`, `in merkle`-style checks), given that trigger execution order is DAG-stabilization-dependent and not caller-controlled.

### Proof of Concept
1. Deploy an AA that stores a merkle root for reward distribution: `if (!is_valid_merkle_proof(trigger.data.element, trigger.data.proof) OR merkle_root(trigger.data.proof) != var['root']) bounce(...)`, paying out to `trigger.address` on success, using `state_var_assignment` (`formula/evaluation.js:1308-1406`) to set `var['root']` and to mark claims.
2. Owner posts root R1 covering User A via a trigger, calling `var['root']=R1'`; persisted via `saveStateVars` (`aa_composer.js:1487-1503`).
3. User A computes an off-chain merkle proof against R1 and broadcasts a claim trigger unit; it is valid but not yet stable.
4. Before User A's trigger stabilizes, the owner (for a legitimate reason such as fixing an error) posts a new trigger with `var['root']=R2`, and this trigger's unit stabilizes first (e.g., due to better DAG placement/lower parent lag) — a realistic and repeatable ordering scenario since `handlePrimaryAATrigger` (`aa_composer.js:91-150`) executes strictly at stabilization time, not submission time.
5. When User A's trigger later stabilizes and executes, `var['root']` now equals R2; the comparison against R1-based proof fails, the AA bounces the trigger, and User A's attached bytes are reduced by `bounce_fees` with no reward received — the reward under R1 is permanently unclaimable once R2 replaces it in state.

### Citations

**File:** aa_composer.js (L91-150)
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
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
									if (arrResponses.length > 1) {
										// copy updatedStateVars to all responses
										if (arrResponses[0].updatedStateVars)
											for (var i = 1; i < arrResponses.length; i++)
												arrResponses[i].updatedStateVars = arrResponses[0].updatedStateVars;
										// merge all changes of balances if the same AA was called more than once
										let assocBalances = {};
										for (let { aa_address, balances } of arrResponses)
											assocBalances[aa_address] = balances; // overwrite if repeated
										for (let r of arrResponses) {
											r.balances = assocBalances[r.aa_address];
											r.allBalances = assocBalances;
										}
									}
									else
										arrResponses[0].allBalances = { [address]: arrResponses[0].balances };
									arrResponses.forEach(function (objAAResponse) {
										if (objAAResponse.objResponseUnit)
											arrPostedUnits.push(objAAResponse.objResponseUnit);
										eventBus.emit('aa_response', objAAResponse);
										eventBus.emit('aa_response_to_unit-'+objAAResponse.trigger_unit, objAAResponse);
										eventBus.emit('aa_response_to_address-'+objAAResponse.trigger_address, objAAResponse);
										eventBus.emit('aa_response_from_aa-'+objAAResponse.aa_address, objAAResponse);
									});
									onDone();
								});
							});
						});
					});
				});
			});
		});
	});
}
```

**File:** aa_composer.js (L1487-1503)
```javascript
	function saveStateVars() {
		if (bSecondary || bBouncing || trigger_opts.bAir)
			return;
		for (var address in stateVars) {
			var addressVars = stateVars[address];
			for (var var_name in addressVars) {
				var state = addressVars[var_name];
				if (!state.updated)
					continue;
				var key = "st\n" + address + "\n" + var_name;
				if (state.value === false) // false value signals that the var should be deleted
					batch.del(key);
				else
					batch.put(key, getTypeAndValue(state.value)); // Decimal converted to string, object to json
			}
		}
	}
```

**File:** formula/evaluation.js (L1308-1363)
```javascript
			case 'state_var_assignment':
				if (!bStateVarAssignmentAllowed)
					return setFatalError("state var assignment not allowed here", { arr }, false, cb);
				var var_name_or_expr = arr[1];
				var rhs = arr[2];
				var assignment_op = arr[3];
				evaluate(var_name_or_expr, function (var_name) {
					if (fatal_error)
						return cb(false);
					if (typeof var_name !== 'string')
						return setFatalError("assignment: state var name must be string, " + var_name_or_expr + " evaluated to " + JSON.stringify(var_name) + ` (${typeof var_name})`, { arr }, false, cb);
					evaluate(rhs, function (res) {
						if (fatal_error)
							return cb(false);
						if (!isValidValue(res) && !(res instanceof wrappedObject))
							return setFatalError("evaluation of rhs " + rhs + " in state var assignment failed: " + JSON.stringify(res), { arr }, false, cb);
						if (Decimal.isDecimal(res))
							res = toDoubleRange(res);
						// state vars can store strings, decimals, objects, and booleans but booleans are treated specially when persisting to the db: true is converted to 1, false deletes the var
						if (res instanceof wrappedObject) {
							if (mci < constants.aa2UpgradeMci)
								res = true;
							else {
								if (assignment_op !== '=' && assignment_op !== '||=')
									return setFatalError(assignment_op + " not supported for object vars", { arr }, false, cb);
								try {
									var json = string_utils.getJsonSourceString(res.obj, true);
								}
								catch (e) {
									return setFatalError("stringify failed: " + e, { arr }, false, cb);
								}
								if (json.length > constants.MAX_STATE_VAR_VALUE_LENGTH)
									return setFatalError("state var value too long when in json: " + json, { arr }, false, cb);
								if (isTooBigObj(res.obj))
									return setFatalError("rhs of state var assignment is too big", { arr }, false, cb);
								res = new wrappedObject(string_utils.cloneDeep(res.obj)); // make a copy
							}
						}
						if (var_name.length > constants.MAX_STATE_VAR_NAME_LENGTH)
							return setFatalError("state var name too long: " + var_name, { arr }, false, cb);
						if (!var_name.isWellFormed())
							return setFatalError("state var name not well formed: " + var_name, { arr }, false, cb);
						if (typeof res === 'string' && !res.isWellFormed())
							return setFatalError("state var value not well formed: " + res, { arr }, false, cb);
					//	if (typeof res === 'boolean')
					//		res = res ? dec1 : dec0;
						if (!stateVars[address])
							stateVars[address] = {};
					//	console.log('---- assignment_op', assignment_op)
						readVar(address, var_name, function (value) {
							if (assignment_op === "=") {
								if (typeof res === 'string' && res.length > constants.MAX_STATE_VAR_VALUE_LENGTH)
									return setFatalError("state var value too long: " + res, { arr }, false, cb);
								stateVars[address][var_name].value = res;
								stateVars[address][var_name].updated = true;
								return cb(true);
```

**File:** formula/evaluation.js (L1768-1807)
```javascript
			case 'is_valid_merkle_proof':
				var element_expr = arr[1];
				var proof_expr = arr[2];
				evaluate(element_expr, function (element) {
					if (fatal_error)
						return cb(false);
					if (typeof element === 'boolean' || isFiniteDecimal(element))
						element = element.toString();
					if (!ValidationUtils.isNonemptyString(element))
						return setFatalError("bad element in is_valid_merkle_proof", { arr }, false, cb);
					evaluate(proof_expr, function (proof) {
						if (fatal_error)
							return cb(false);
						let res;
						var objProof;
						if (proof instanceof wrappedObject)
							objProof = proof.obj;
						else if (typeof proof === 'string') {
							if (proof.length > 1024)
								return setFatalError("proof is too large", { arr }, false, cb);
							objProof = merkle.deserializeMerkleProof(proof);
						}
						else // can't be valid proof
							return cb(false);
						if (bPostPemCurvesFix) {
							if (!Array.isArray(objProof.siblings) || !objProof.siblings.every(ValidationUtils.isNonemptyString))
								return cb(false);
							if (objProof.siblings.length > 50)
								return cb(false);
						}
						try {
							res = merkle.verifyMerkleProof(element, objProof);
						}
						catch (e) {
							res = false;
						}
						cb(res);
					});
				});
				break;
```
