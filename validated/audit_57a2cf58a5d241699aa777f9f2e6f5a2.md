### Title
Unhandled `throw Error("no src_coin")` crash when validating a normally-broadcast payment referencing a private, fixed-denomination asset - (File: validation.js)

### Summary
The CVE describes an FFmpeg assertion failure caused by inconsistency between a context field (`profile`) and a derived state field (`studio_profile`), which is never reconciled for all code paths and crashes the decoder. The analogous pattern in `ocore` is in `validatePaymentInputsAndOutputs()` in [1](#0-0) , where the code assumes that whenever `objAsset.is_private && objAsset.fixed_denominations` is true, `objValidationState.src_coin` has already been populated by the private-payment-chain validator. That precondition is only established by the private-chain-specific caller in [2](#0-1) , not by the generic unit-validation entry point `validate()` used for ordinary broadcast/incoming units in [3](#0-2) . When a "transfer" input for a private, fixed-denomination asset is validated through the normal path (any peer/unit-poster submitted unit, not through `indivisible_asset.js`'s private-chain flow), `objValidationState.src_coin` is `undefined`, and the code unconditionally does `throw Error("no src_coin")` (and similar `throw Error(...)` for `src_output`/`denomination`/`amount`) instead of returning a graceful `callback(err)`.

### Finding Description
`validatePaymentInputsAndOutputs()` handles the `"transfer"` input case for payment messages. For public/non-private assets or divisible private assets, missing/failed lookups are surfaced via `cb(...)` (a normal validation error), letting `validate()` reply `ifUnitError` cleanly. But for `objAsset.is_private && objAsset.fixed_denominations`, the code takes an entirely different branch that skips the database lookup and instead requires `objValidationState.src_coin` to already carry `src_output`, `denomination`, and `amount` — see [1](#0-0) . This field is set only inside `validatePrivatePayment()` in `indivisible_asset.js`, specifically at [4](#0-3) , which is reached only through the dedicated private-payment-chain APIs (`private_payment.js`, `indivisible_asset.js`), never through the generic `validate(objJoint, callbacks)` entry point that processes ordinary units received from peers or posted directly, shown at [3](#0-2)  and the async pipeline in [5](#0-4) .

Consequently, if a unit is submitted through the ordinary validation pipeline (e.g., a crafted joint sent directly to a node, or relayed from another peer) containing a payment message whose `asset` refers to an existing private, fixed-denomination asset and whose input is of type `"transfer"`, `validatePaymentInputsAndOutputs()` reaches the private-asset branch, finds `objValidationState.src_coin` unset, and executes `throw Error("no src_coin")`. This throw occurs deep inside a `conn.query` callback / `async.eachSeries` iterator that is not wrapped by validation's own error-callback machinery — it is a genuine unhandled JS exception, not a call to `callback(err)`. Unhandled exceptions of this kind in Node.js propagate up the stack and, unless caught at the process level, terminate the process (denial of service), mirroring the FFmpeg assertion-failure crash pattern: an internal consistency invariant assumed by one code path (`profile`/`studio_profile` in FFmpeg; `src_coin` populated in ocore) is violated when reached via an alternate path, and the response is a hard crash rather than a validation error.

### Impact Explanation
This is a network-wide denial-of-service vector: any actor who can get a unit validated through the normal path (author of the unit, or any node relaying it) can construct a payment message that references a real private/fixed-denomination asset with a `"transfer"` input, entirely bypassing the wallet's private-chain building logic. Every full node that receives and validates such a unit hits the same unhandled `throw`, potentially crashing the node process. This matches the CVE's severity profile (assertion-style crash reachable via malformed but structurally valid input), causing "a network unable to confirm new units" if propagated widely, since affected nodes go down when validating the malicious unit.

### Likelihood Explanation
The private, fixed-denomination asset type is a standard, reachable asset kind that any asset issuer can define (`is_private` + `fixed_denominations` in an asset definition message), and the attacker doesn't need special privileges — only knowledge of an existing private asset's hash/denomination, which is public (only outputs/balances are private, not the asset definition or its parameters). Building a syntactically valid payment message with a `"transfer"` input referencing that asset requires no cryptographic secrets, since the code throws before verifying spend proofs or outputs authenticity — the crash occurs purely due to the missing `src_coin` precondition, before any signature/spend-proof/ownership check for that branch. This makes the trigger cheap and reliable.

### Recommendation
In `validatePaymentInputsAndOutputs()` at [6](#0-5) , replace the `throw Error(...)` calls guarding `src_coin`/`src_output`/`denomination`/`amount` with normal `return cb(...)` validation errors. This preserves the invariant check for legitimate internal callers (private-chain validation) while ensuring that any unit reaching this code through the generic `validate()` entry point without a properly pre-populated `objValidationState.src_coin` is rejected as an ordinary unit error instead of crashing the process. Additionally, consider explicitly rejecting `"transfer"` inputs for private, fixed-denomination assets earlier in the generic validation path (i.e., before reaching this branch) if `src_coin` was never intended to be settable outside the private-chain flow, making the two code paths structurally distinguishable.

### Proof of Concept
1. Identify or issue a private, fixed-denomination asset (`is_private: true`, `fixed_denominations: true` in its definition message) — asset definitions are public even though outputs are private.
2. Craft a unit with a `payment` message: `{"app":"payment","payload":{"asset":"<private_fixed_denom_asset_hash>","denomination":<d>,"inputs":[{"type":"transfer","unit":"<any_hash>","message_index":0,"output_index":0}],"outputs":[...]}}`, signed normally by the author so it passes author/signature checks up to `validatePaymentInputsAndOutputs`.
3. Submit this unit directly to a full node via the standard joint submission path (i.e., not through `private_payment.js`/wallet private-chain building), so it goes through the plain `validate()` entry point in `validation.js`.
4. During processing, `validatePaymentInputsAndOutputs()` reaches the `objAsset.is_private && objAsset.fixed_denominations` branch with `objValidationState.src_coin` unset, and executes `throw Error("no src_coin")`, producing an unhandled exception that can crash the validating node process.

### Citations

**File:** validation.js (L118-180)
```javascript
function validate(objJoint, callbacks, external_conn) {
	
	var objUnit = objJoint.unit;
	if (typeof objUnit !== "object" || objUnit === null)
		throw Error("no unit object");
	if (!objUnit.unit)
		throw Error("no unit");
	
	console.log("\nvalidating joint identified by unit "+objJoint.unit.unit);
	
	if (!isStringOfLength(objUnit.unit, constants.HASH_LENGTH))
		return callbacks.ifJointError("wrong unit length");
	
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}

	const bGenesis = storage.isGenesisUnit(objUnit.unit);

	var bAA = false;
	if (objJoint.aa) {
		bAA = true;
		var aa_mci = objJoint.aa_mci;
		delete objJoint.aa;
		delete objJoint.aa_mci;
	}
	else {
		if (isArrayOfLength(objUnit.authors, 1) && !isNonemptyObject(objUnit.authors[0].authentifiers) && !objUnit.content_hash && !conf.bLight)
			return callbacks.ifTransientError("possible AA");
	}
	
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");

	if (!isObjectWellFormed(objJoint))
		return bAA ? callbacks.ifUnitError("unit contains invalid string (lone surrogate or null byte)") : callbacks.ifJointError("unit contains invalid string (lone surrogate or null byte)");

	if (objJoint.unsigned){
		if (hasFieldsExcept(objJoint, ["unit", "unsigned"]))
			return callbacks.ifJointError("unknown fields in unsigned unit-joint");
	}
	else if ("ball" in objJoint){
		if (!isStringOfLength(objJoint.ball, constants.HASH_LENGTH))
			return callbacks.ifJointError("wrong ball length");
		if (hasFieldsExcept(objJoint, ["unit", "ball", "skiplist_units"]))
			return callbacks.ifJointError("unknown fields in ball-joint");
		if ("skiplist_units" in objJoint){
			if (!isNonemptyArray(objJoint.skiplist_units))
				return callbacks.ifJointError("missing or empty skiplist array");
			//if (objUnit.unit.charAt(0) !== "0")
			//    return callbacks.ifJointError("found skiplist while unit doesn't start with 0");
		}
	}
	else{
		if (hasFieldsExcept(objJoint, ["unit"]))
			return callbacks.ifJointError("unknown fields in unit-joint");
	}
	
```

**File:** validation.js (L354-496)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");

	mutex.lock(arrAuthorAddresses, function(unlock){
		
		var conn = null;
		var commit_fn = null;
		var start_time = null;

		async.series(
			[
				function(cb){
					if (external_conn) {
						conn = external_conn;
						start_time = Date.now();
						commit_fn = function (cb2) { cb2(); };
						return cb();
					}
					db.takeConnectionFromPool(function(new_conn){
						conn = new_conn;
						start_time = Date.now();
						commit_fn = function (cb2) {
							conn.query(objValidationState.bAdvancedLastStableMci ? "COMMIT" : "ROLLBACK", function () { cb2(); });
						};
						conn.query("BEGIN", function(){cb();});
					});
				},
				function(cb){
					profiler.start();
					checkDuplicate(conn, objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-checkDuplicate');
					profiler.start();
					objUnit.content_hash ? cb() : validateHeadersCommissionRecipients(objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-hc-recipients');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateHashTreeBall(conn, objJoint, cb);
				},
				function(cb){
					profiler.stop('validation-hash-tree-ball');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateParentsExistAndOrdered(conn, objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-parents-exist');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateHashTreeParentsAndSkiplist(conn, objJoint, cb);
				},
				function(cb){
					profiler.stop('validation-hash-tree-parents');
				//	profiler.start(); // conflicting with profiling in determineIfStableInLaterUnitsAndUpdateStableMcFlag
					!objUnit.parent_units
						? cb()
						: validateParents(conn, objJoint, objValidationState, cb);
				},
				function(cb){
				//	profiler.stop('validation-parents');
					profiler.start();
					!objJoint.skiplist_units
						? cb()
						: validateSkiplist(conn, objJoint.skiplist_units, cb);
				},
				function(cb){
					profiler.stop('validation-skiplist');
					validateWitnesses(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
				function(cb){
					profiler.start();
					validateAuthors(conn, objUnit.authors, objUnit, objValidationState, cb);
				},
				function(cb){
					profiler.stop('validation-authors');
					profiler.start();
					objUnit.content_hash ? cb() : validateMessages(conn, objUnit.messages, objUnit, objValidationState, cb);
				}
			], 
			function(err){
				if(err){
					if (profiler.isStarted())
						profiler.stop('validation-advanced-stability');
					// We might have advanced the stability point and have to commit the changes as the caches are already updated.
					// There are no other updates/inserts/deletes during validation
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('failed validation', consumed_time);
						console.log(objUnit.unit+" validation "+JSON.stringify(err)+" took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						unlock();
						if (typeof err === "object"){
							if (err.error_code === "unresolved_dependency")
								callbacks.ifNeedParentUnits(err.arrMissingUnits, err.bRequestPrunedContent);
							else if (err.error_code === "need_hash_tree") // need to download hash tree to catch up
								callbacks.ifNeedHashTree();
							else if (err.error_code === "invalid_joint") // ball found in hash tree but with another unit
								callbacks.ifJointError(err.message);
							else if (err.error_code === "transient")
								callbacks.ifTransientError(err.message);
							else
								throw Error("unknown error code");
						}
						else
							callbacks.ifUnitError(err);
					});
				}
				else{
					profiler.stop('validation-messages');
					profiler.start();
					commit_fn(function(){
						var consumed_time = Date.now()-start_time;
						profiler.add_result('validation', consumed_time);
						console.log(objUnit.unit+" validation ok took "+consumed_time+"ms");
						if (!external_conn)
							conn.release();
						profiler.stop('validation-commit');
						if (objJoint.unsigned){
							unlock();
							callbacks.ifOkUnsigned(objValidationState.sequence === 'good');
						}
						else
							callbacks.ifOk(objValidationState, unlock);
					});
				}
			}
		); // async.series
		
	});
	
```

**File:** validation.js (L2412-2424)
```javascript
					// for private fixed denominations assets, we can't look up src output in the database 
					// because we validate the entire chain before saving anything.
					// Instead we prepopulate objValidationState with denomination and src_output 
					if (objAsset && objAsset.is_private && objAsset.fixed_denominations){
						if (!objValidationState.src_coin)
							throw Error("no src_coin");
						var src_coin = objValidationState.src_coin;
						if (!src_coin.src_output)
							throw Error("no src_output");
						if (!isPositiveInteger(src_coin.denomination))
							throw Error("no denomination in src coin");
						if (!isPositiveInteger(src_coin.amount))
							throw Error("no src coin amount");
```

**File:** indivisible_asset.js (L134-139)
```javascript
				arrFuncs.push(validateSourceOutput);
				objValidationState.src_coin = {
					src_output: src_output,
					denomination: payload.denomination,
					amount: prev_hidden_output.amount
				};
```
