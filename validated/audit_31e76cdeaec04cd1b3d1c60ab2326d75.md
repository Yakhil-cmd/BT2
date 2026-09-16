### Title
Unhandled `throw Error` in private-asset double-spend handling crashes the node - ([File: validation.js])

### Summary
CVE-2024-26369 describes a crash (SIGABRT) that occurs in FastDDS's `HistoryQosPolicy` when it receives unexpected `DataWriter` data that the library doesn't gracefully reject — instead of returning a validation error, the process aborts. The structurally equivalent pattern in `ocore` is a `throw Error(...)` placed deep inside the payment-validation pipeline that a private-payment counterparty can trigger with crafted (but structurally valid) private-payment data, causing an uncaught exception instead of a normal validation rejection.

### Finding Description
When validating a divisible payment input, `validatePaymentInputsAndOutputs` performs a double-spend check via `checkInputDoubleSpend`. For private assets, if a double-spend is detected and the accompanying spend proof does not resolve it, the code does not return a normal validation error to the caller — it throws an unhandled `Error`: [1](#0-0) 

This `throw` happens inside an asynchronous callback (`onDone`) invoked from `checkForDoublespends`, several callback layers removed from the synchronous call stack of `validate()`. Because it occurs inside nested `conn.query`/`async` callbacks rather than being returned through the `callback` chain used everywhere else in this file (e.g. `return callback("...")`), it cannot be caught by any surrounding `try/catch` in the validation call chain (see the wrapping `async.series` construct in `validate()` at [2](#0-1)  which only catches errors passed through the `cb`/`callback` convention, not exceptions thrown asynchronously). The result is a genuine JS exception thrown outside of any promise/callback error-handling path, which in Node.js becomes an `uncaughtException` and can crash the whole process — the same class of "unexpected input reaches a code path that aborts the process instead of failing safely" that CVE-2024-26369 describes for `HistoryQosPolicy`.

This code path is reachable by an ordinary private-payment counterparty: when receiving a chain of private elements (via `indivisible_asset.js`/wallet private-payment handling) that is replayed through `validation.js`'s `validatePayment` → `validatePaymentInputsAndOutputs`, a peer can construct a private payment referencing an input that is already a stable double-spend where the supplied spend proof does not match, forcing execution into this `throw Error` branch instead of the normal `cb(err)` (validation-failure) branch.

### Impact Explanation
A crash triggered by an unhandled exception during unit/private-payment validation takes down the full node process. If reproducible on-demand by any private-payment counterparty, an attacker can repeatedly crash a target's wallet/full node, denying it the ability to validate/confirm units — matching the "network unable to confirm new units" impact bar. It does not appear to enable spending manipulation directly, but is a process-availability bug directly analogous in class to the reported CVE (crash on receipt of unexpected data instead of graceful error handling).

### Likelihood Explanation
Reaching this branch requires: (1) being a private-payment counterparty who can send a private-payment chain to the victim, and (2) crafting the private payment/spend-proof combination such that `checkForDoublespends`'s `onDone` callback receives a non-null `err` while `objAsset.is_private && !conf.bLight`. This is a non-trivial but plausible sequence achievable by any protocol participant without special privileges, since private-payment chains and spend proofs are fully attacker-controlled inputs on the wire.

### Recommendation
Replace the `throw Error("spend proof didn't help: "+err)` with a proper validation-failure return through the callback chain (e.g. `return cb(err)` /`return callback(err)`), consistent with every other check in `validatePaymentInputsAndOutputs`, so malformed/unresolved private double-spends are rejected as invalid units rather than crashing the process. Audit all other `throw Error(...)` calls inside async callbacks in `validation.js` (e.g., lines 2416–2424, 2451, 2458) for the same asynchronous-uncaught-exception risk, and add a top-level safety net (or convert to `callback(err)`) so that no externally-influenced data path can trigger an uncaught exception.

### Proof of Concept
Conceptual PoC (cannot be fully executed without live wallet infrastructure, but the trigger conditions are derivable from the code):
1. Attacker (private-payment counterparty) sends the victim a private-payment chain for a private, non-fixed-denomination asset whose underlying source output has already been spent elsewhere by the same address (a double-spend), while supplying a `spend_proofs` entry that does not correctly resolve the conflict.
2. Victim node processes the incoming private payment through `validatePayment` → `validatePaymentInputsAndOutputs` → `checkInputDoubleSpend` → `checkForDoublespends`.
3. `checkForDoublespends` calls back with a non-null `err` (unresolved double-spend) for a private, non-light node: `onDone(err)` at [1](#0-0)  executes `throw Error("spend proof didn't help: "+err)`.
4. Because this throw occurs inside an async DB-callback context, it is not caught by the normal validation error path and surfaces as an uncaught exception, crashing the victim's node process.

Note: I was unable to fully confirm whether `network.js`'s `uncaughtException` handler (referenced but not inspected in depth due to tool-call limits) intercepts and gracefully recovers from this specific throw, or whether it still results in a hard process exit — this should be verified directly in the repository before treating the impact as fully confirmed.

### Citations

**File:** validation.js (L363-444)
```javascript
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
```

**File:** validation.js (L2297-2304)
```javascript
					function onDone(err){
						if (err && objAsset && objAsset.is_private && !conf.bLight)
							throw Error("spend proof didn't help: "+err);
					//	if (objAsset)
					//		profiler2.stop('checkInputDoubleSpend');
						cb2(err);
					}
				);
```
