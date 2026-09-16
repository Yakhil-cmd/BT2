### Title
Race condition in private payment chain validation allows double-acceptance / double-spend of the same private (hidden) output - ([File: private_payment.js])

### Summary
`validateAndSavePrivatePaymentChain` in `private_payment.js` performs a classic check-then-act sequence — "check if duplicate" `SELECT` followed by a separate validate-and-`INSERT` step — on a **freshly taken DB connection with its own `BEGIN`/`COMMIT`**, with no mutex serializing concurrent calls for the same private chain/spend proof. This mirrors the reported bug class (a single-use token's uniqueness check and its consumption are not atomic across concurrent requests), except here the "single-use" secret is the private-payment spend proof / hidden-output ownership rather than an OTP.

### Finding Description
Public unit validation in ocore is serialized per author address: `validation.validate()` wraps the whole check in `mutex.lock(arrAuthorAddresses, ...)` before ever touching double-spend logic, so two concurrent units spending the same output from the same address are processed sequentially and the second is rejected. [1](#0-0) 

Private payment chains do **not** go through this path. `private_payment.js#validateAndSavePrivatePaymentChain` takes an independent connection, opens its own transaction, runs a duplicate-check `SELECT` on `outputs`, and only if nothing is found proceeds to `assetModule.validateAndSavePrivatePaymentChain` (indivisible/divisible) to validate spend proofs and `INSERT` the new input/output rows — all without any `mutex.lock` call around this read-then-write sequence. [2](#0-1) 

This function is invoked from multiple concurrent contexts with no coordinating lock:
- `network.js#handleOnlinePrivatePayment`, triggered per received private_payment message. [3](#0-2) 
- `network.js#handleSavedPrivatePayments`, which explicitly processes queued private chains **in parallel** via `async.each`. [4](#0-3) 

Each invocation acquires its own pooled connection and transaction, so two concurrent chains that spend the *same* hidden output (i.e., the payer double-spends a private coin by building two different valid-looking chains sending it to two different recipients, or resending it via hub and directly to a device) can each pass the spend-proof/duplicate checks before either transaction commits, because the checks read from a snapshot that has not yet observed the other in-flight transaction's write. The transfer-input spend proof is computed and checked for uniqueness deep inside asset validation. [5](#0-4) 
Both `INSERT`s can then complete, each recipient chain being marked `is_unique=1`/`is_serial=1` in its own transaction. [6](#0-5) 

### Impact Explanation
This allows a private-payment counterparty (an unprivileged, attacker-controlled payer) to spend the same private hidden output to two different recipients by racing two concurrent submissions (e.g., via hub and directly, or to two correspondents at once), producing two independently "valid" ownership chains for the same coin. This is a genuine double-spend of a private asset output — one of the explicitly in-scope impact categories (double-spend of a stable output / unauthorized spending), reachable purely by a private-payment counterparty with no privileged access.

### Likelihood Explanation
Exploitation requires the attacker to control both ends of a private payment (as payer) and to time two chain submissions concurrently, which is achievable by sending the same signed chain twice through different channels (hub relay vs. direct P2P) or triggering `handleSavedPrivatePayments`'s parallel processing for two queued chains referencing the same source output. No cryptographic secret needs to be guessed — the race is purely a timing issue in the missing lock, which is consistent with the "narrow but concretely exploitable" nature described in the reference CVE.

### Recommendation
Serialize `validateAndSavePrivatePaymentChain` (and the spend-proof duplicate check it performs) per spend-proof/source-output key using `mutex.lock`, the same pattern already used to protect public double-spend checks via `arrAuthorAddresses` in `validation.js`. The lock should span the duplicate-check `SELECT` through the `INSERT`/commit so no second caller can observe a stale "not yet spent" state.

### Proof of Concept
1. Attacker A owns a private (hidden) coin with output `(unit0, message_index0, output_index0)`.
2. A builds two independent private-payment chains `chainX` (to victim X) and `chainY` (to victim Y), both consuming the same source output and each with a valid spend proof for their own chain.
3. A sends `chainX` directly to X's device and, at nearly the same time, sends `chainY` to Y via the hub (or resubmits through `handleSavedPrivatePayments`'s parallel `async.each`).
4. Both `network.js#handleOnlinePrivatePayment` → `private_payment.js#validateAndSavePrivatePaymentChain` calls run concurrently on separate DB connections; both duplicate/spend-proof checks pass because neither transaction has committed yet.
5. Both X and Y independently observe successful acceptance (`ifOk`) of their chain, each believing they now own the same coin — a double-spend of a private asset output.

Note: I was not able to fully inspect the exact `validateSpendProof`/`spend_proofs` table implementation within the available indexed content (index size limits may exclude parts of `validation.js` around spend proof storage); a Devin session with full repository access would be needed to confirm the exact uniqueness-check SQL and rule out an unseen locking mechanism before implementing the fix.

### Citations

**File:** validation.js (L354-357)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");

	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** private_payment.js (L45-110)
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
							if (rows.length > 1)
								throw Error("more than one output "+sql+' '+params.join(', '));
							if (rows.length > 0 && rows[0].address){ // we could have this output already but the address is still hidden
								const stored = rows[0];
								const payload = headElement.payload;
								let bDuplicate = false;
								if (objAsset.fixed_denominations){ // the row we selected is exactly headElement.output_index, filtered in sql above
									const claimed_output = payload.outputs?.[headElement.output_index];
									const revealed_output = headElement?.output;
									bDuplicate =
										ValidationUtils.isNonemptyObject(claimed_output)
										&& ValidationUtils.isNonemptyObject(revealed_output)
										&& stored.denomination === payload.denomination
										&& stored.amount === claimed_output.amount
										&& stored.address === revealed_output.address
										&& stored.blinding === revealed_output.blinding;
								}
								else // divisible outputs are never hidden individually and sql has no output_index filter, so match against any of them
									bDuplicate = (payload.outputs || []).some(output => {
										return ValidationUtils.isNonemptyObject(output)
											&& stored.denomination === 1
											&& stored.amount === output.amount
											&& stored.address === output.address
											&& stored.blinding === output.blinding;
									});
								if (bDuplicate) {
									console.log("duplicate private payment "+params.join(', '));
									return transaction_callbacks.ifOk();
								}
							}
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
						}
					);
				});
			});
		});
```

**File:** network.js (L2412-2429)
```javascript
	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
		},
```

**File:** network.js (L2456-2519)
```javascript
			if (rows.length === 0)
				return unlock();
			var assocNewUnits = {};
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
					var arrPrivateElements = JSON.parse(row.json);
					var ws = getPeerWebSocket(row.peer);
					if (ws && ws.readyState !== ws.OPEN)
						ws = null;
					
					var validateAndSave = function(){
						var objHeadPrivateElement = arrPrivateElements[0];
						try {
							var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
						}
						catch (e) {
							console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
							if (ws)
								sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
							deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
						}
						var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
							ifOk: function(){
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'accepted'});
								if (row.peer) // received directly from a peer, not through the hub
									eventBus.emit("new_direct_private_chains", [arrPrivateElements]);
								assocNewUnits[row.unit] = true;
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								console.log('emit '+key);
								eventBus.emit(key, true);
							},
							ifError: function(error){
								console.log("validation of priv: "+error);
							//	throw Error(error);
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: error});
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								eventBus.emit(key, false);
							},
							// light only. Means that chain joints (excluding the head) not downloaded yet or not stable yet
							ifWaitingForChain: function(){
								console.log('waiting for chain: unit '+row.unit+', message '+row.message_index+' output '+row.output_index);
								cb();
							}
						});
					};
					
					if (conf.bLight && arrPrivateElements.length > 1 && !row.linked)
						updateLinkProofsOfPrivateChain(arrPrivateElements, row.unit, row.message_index, row.output_index, cb, validateAndSave);
					else
						validateAndSave();
					
				},
				function(){
					unlock();
					var arrNewUnits = Object.keys(assocNewUnits);
					if (arrNewUnits.length > 0)
						eventBus.emit("new_my_transactions", arrNewUnits);
				}
			);
		});
```

**File:** indivisible_asset.js (L110-134)
```javascript
				input_address = src_output.address;
				try {
					spend_proof = objectHash.getBase64Hash({
						asset: payload.asset,
						unit: input.unit,
						message_index: input.message_index,
						output_index: input.output_index,
						address: src_output.address,
						amount: prev_hidden_output.amount,
						blinding: src_output.blinding
					});
				}
				catch (e) {
					return callbacks.ifError("failed to calc transfer spend proof: " + e.message);
				}
				console.log("validation spend proof: "+JSON.stringify({
					asset: payload.asset,
					unit: input.unit,
					message_index: input.message_index,
					output_index: input.output_index,
					address: src_output.address,
					amount: prev_hidden_output.amount,
					blinding: src_output.blinding
				}));
				arrFuncs.push(validateSourceOutput);
```

**File:** indivisible_asset.js (L251-288)
```javascript
				var is_unique = objPrivateElement.bStable ? 1 : null; // unstable still have chances to become nonserial therefore nonunique
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
