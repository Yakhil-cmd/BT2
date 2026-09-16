### Title
Race condition in private payment duplicate-check bypasses uniqueness enforcement, allowing concurrent processing of the same private-payment chain - (File: private_payment.js)

### Summary
`CVE-2021-35937` describes a race condition in rpm that lets a local unprivileged user bypass a "check-then-act" validation (the checks introduced for CVE-2017-7500/7501) because the check and the subsequent use of the resource are not atomic. Ocore has a structurally identical check-then-act gap in the private-payment acceptance path: the "is this chain a duplicate" check and the subsequent INSERT of `inputs`/`outputs` rows are not protected by any mutex, and the caller processes multiple pending private-payment rows in parallel.

### Finding Description
`private_payment.js`'s `validateAndSavePrivatePaymentChain` opens its own DB connection, starts a `BEGIN` transaction, runs a `SELECT` to detect whether the output has already been recorded, and only if that `SELECT` returns nothing (or a non-matching row) proceeds to call `divisibleAsset.validateAndSavePrivatePaymentChain` / `indivisibleAsset.validateAndSavePrivatePaymentChain` to `INSERT` the `inputs`/`outputs` rows: [1](#0-0) [2](#0-1) 

Unlike unit validation in `validation.js`, which serializes concurrent validations of the same author addresses with `mutex.lock(arrAuthorAddresses, ...)` before doing any duplicate/double-spend check: [3](#0-2) 

...`validateAndSavePrivatePaymentChain` in `private_payment.js` acquires no address- or output-scoped lock at all around its "check-then-insert" sequence. The only mutex in the call path is `mutex.lock(["saved_private"])` in `network.js`, which merely guards iteration over the `unhandled_private_payments` queue — and the rows are then handled with `async.each`, i.e. **in parallel**, as the code itself documents ("handle different chains in parallel"): [4](#0-3) 

If the same private-payment counterparty (or a paired device forwarding the same private chain) causes two rows referencing the same `unit`/`message_index`/`output_index` to exist in `unhandled_private_payments` (e.g. resent via two different peers, or resent while the first handling is still in flight), both rows are processed concurrently. Each concurrent invocation opens its own connection/transaction, runs the duplicate-check `SELECT` before either transaction has committed its `INSERT`, and both can observe "no existing row" and proceed to insert. This is the same class of bug as CVE-2021-35937: a security-relevant check (uniqueness/duplicate detection) is evaluated against state that can still change before the action it gates is committed, because the check and the write are not covered by a single lock/transaction boundary that is exclusive per resource (here, per output).

The indivisible-asset writer additionally uses `INSERT OR IGNORE`/`INSERT IGNORE` for the `inputs` and `outputs` rows: [5](#0-4) 
which means that even if the underlying unique key eventually rejects the second writer's row, the conflict is silently swallowed rather than surfaced as an error, so the second concurrent execution can appear to succeed (`ifOk()` called) while its output-address/blinding assignment for that slot never actually took effect — or, depending on ordering of the `UPDATE outputs ... WHERE ... AND is_spent=0` in the same block, a race between "insert new output row" and "mark existing output spent" can leave `is_spent`/`address`/`blinding` in an inconsistent state relative to what the two concurrent private-payment senders each believe was recorded.

### Impact Explanation
A private-payment counterparty (or colluding pair of devices) that races two copies of the same (or two conflicting) private-payment chains into `unhandled_private_payments` can drive two concurrent transactions through the duplicate-check-then-insert path without serialization. Depending on backend isolation semantics and the `INSERT IGNORE` behavior in the indivisible path, this can result in the receiving wallet/hub accepting inconsistent state for the same private output (e.g., recording it as both received and not received, or under two different owning addresses), undermining the private-payment ledger's consistency guarantees that the unique constraints on `inputs`/`outputs` are supposed to enforce. This is a node-disagreement / bookkeeping-integrity issue in the private-payment chain handling rather than a straightforward public double-spend, since public spends are additionally protected by the `arrAuthorAddresses` mutex and DB-level `UNIQUE` constraints in `validation.js`/`writer.js`.

### Likelihood Explanation
Exploitability requires:
1. Getting two (or more) rows for the same private-payment chain into `unhandled_private_payments` concurrently — plausible since a private-payment counterparty controls when/how many times a chain is sent, and light wallets/hubs can receive it from multiple peers.
2. The `async.each` parallel processing in `network.js` and the lack of a per-output mutex in `private_payment.js` to actually create overlapping transactions.

I was not able to fully verify (due to no further tool calls) whether `unhandled_private_payments` has a `UNIQUE` constraint on `(unit, message_index, output_index)` that would prevent duplicate rows from being queued in the first place, which is the main factor that would reduce or eliminate the practical likelihood of triggering the race. This should be checked directly in the schema (`initial-db/*.sql`, table `unhandled_private_payments`) before treating this as confirmed exploitable — I flag this as an open verification item rather than a certainty.

### Recommendation
- Wrap the duplicate-check `SELECT` and subsequent `INSERT`s in `private_payment.js`'s `validateAndSavePrivatePaymentChain` in a `mutex.lock` keyed by `(unit, message_index, output_index)` (or by the asset/address), mirroring the `mutex.lock(arrAuthorAddresses, ...)` pattern already used in `validation.js`, so that concurrent chains referencing the same output cannot both pass the duplicate check before either commits.
- Process rows from `unhandled_private_payments` referencing the same underlying output serially rather than via unconditional `async.each` parallelism, or dedupe by `(unit, message_index, output_index)` before dispatching.
- Replace `INSERT IGNORE`/`INSERT OR IGNORE` in `indivisible_asset.js`'s private-chain save path with explicit conflict detection that surfaces an error to the caller instead of silently succeeding, so a lost race is reported rather than masked.
- Verify (and if absent, add) a `UNIQUE` constraint on `unhandled_private_payments(unit, message_index, output_index)` to prevent duplicate queuing at the source.

### Proof of Concept
1. As a private-payment counterparty, construct one valid private-payment chain for a given `(unit, message_index, output_index)`.
2. Deliver it to the target node twice in quick succession, via two different peer connections (or by re-sending before the first `handleSavedPrivatePayments` pass completes), so two rows for the same chain exist in `unhandled_private_payments` at the same time.
3. Because `network.js`'s `handleSavedPrivatePayments` dispatches all pending rows via `async.each` (parallel) and `private_payment.js`'s `validateAndSavePrivatePaymentChain` opens an independent connection/transaction per invocation with no output-scoped mutex, both invocations' duplicate-check `SELECT`s can run before either `INSERT` commits.
4. Observe whether both invocations report `ifOk()` and whether the resulting `inputs`/`outputs` rows for that output end up in a consistent state — in the indivisible-asset path, `INSERT IGNORE` will mask a losing writer's conflict rather than error it out, which can be confirmed by comparing the final `address`/`blinding`/`is_spent` values in `outputs` against what each of the two concurrent senders intended to set. This part requires a live concurrency test against the actual DB backend (sqlite/mysql) to confirm observable divergence, which I was not able to execute here.

### Citations

**File:** private_payment.js (L45-73)
```javascript
			db.takeConnectionFromPool(function(conn){
				conn.query("BEGIN", function(){
					var transaction_callbacks = {
						ifError: function(err){
							conn.query("ROLLBACK", function(){
								conn.release();
								callbacks.ifError(err);
							});
						},
						ifOk: function(){
							conn.query("COMMIT", function(){
								conn.release();
								callbacks.ifOk();
							});
						}
					};
					// check if duplicate
					var sql = "SELECT address, denomination, amount, blinding FROM outputs WHERE unit=? AND asset=? AND message_index=?";
					var params = [headElement.unit, asset, headElement.message_index];
					if (objAsset.fixed_denominations){
						if (!ValidationUtils.isNonnegativeInteger(headElement.output_index))
							return transaction_callbacks.ifError("no output index in head private element");
						sql += " AND output_index=?";
						params.push(headElement.output_index);
					}
					conn.query(
						sql, 
						params, 
						function(rows){
```

**File:** private_payment.js (L99-106)
```javascript
								if (bDuplicate) {
									console.log("duplicate private payment "+params.join(', '));
									return transaction_callbacks.ifOk();
								}
							}
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
						}
```

**File:** validation.js (L354-380)
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
```

**File:** network.js (L2451-2461)
```javascript
	lock(["saved_private"], function(unlock){
		var sql = unit
			? "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments WHERE unit="+db.escape(unit)
			: "SELECT json, peer, unit, message_index, output_index, linked FROM unhandled_private_payments CROSS JOIN units USING(unit)";
		db.query(sql, function(rows){
			if (rows.length === 0)
				return unlock();
			var assocNewUnits = {};
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
```

**File:** indivisible_asset.js (L253-288)
```javascript
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
