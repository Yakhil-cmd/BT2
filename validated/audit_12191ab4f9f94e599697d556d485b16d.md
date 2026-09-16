### Title
TOCTOU race in private payment chain acceptance allows double-spend of a private-asset output - (File: private_payment.js)

### Summary
`private_payment.validateAndSavePrivatePaymentChain()` implements a classic check-then-use race: it queries the `outputs` table for a possible duplicate/already-spent private output, and only *after* that read completes does it hand off to `indivisible_asset.validateAndSavePrivatePaymentChain()` / `divisible_asset.validateAndSavePrivatePaymentChain()` to validate spend proofs and finally INSERT the new spend. Unlike ordinary unit validation in `validation.js`, which is fully serialized per set of author addresses via `mutex.lock(arrAuthorAddresses, ...)` [1](#0-0) , this private-payment code path takes a fresh DB connection and a `BEGIN`/`COMMIT` transaction with **no mutex at all** guarding the (unit, message_index[, output_index]) key being checked and written [2](#0-1) .

### Finding Description
The check ("is this output already known/spent?") and the use (insert the new input/output rows, mark `is_spent=1`) are two separate operations, separated by asynchronous DB round-trips, and are not protected by any `mutex.lock()` call:

1. `validateAndSavePrivatePaymentChain()` opens a new pooled connection, starts a transaction, and runs a `SELECT` to see if the output already exists / was already claimed: [3](#0-2) 
2. If not flagged as a duplicate, it forwards to the asset-specific saver, which independently re-validates spend proofs by querying `spend_proofs`/`outputs` (`validateSpendProofs` in `divisible_asset.js`) [4](#0-3)  or `validateSpendProof`/`validateSourceOutput` in `indivisible_asset.js` [5](#0-4) , and only then issues the `INSERT ... INTO inputs` / `UPDATE outputs SET is_spent=1` queries [6](#0-5) [7](#0-6) .

Two private chains that spend the *same* private output (e.g., a malicious or compromised paired device replaying/re-sending a private-payment chain, or the same chain delivered twice through different code paths) can each be processed on their own pooled connection concurrently:
- `network.handleOnlinePrivatePayment()` invokes `privatePayment.validateAndSavePrivatePaymentChain()` directly when the unit is already known [8](#0-7) .
- `network.handleSavedPrivatePayments()` processes multiple unhandled private payments **in parallel** (`async.each`, not `eachSeries`) and calls the same `validateAndSavePrivatePaymentChain()` for each row without any `mutex.lock` keyed on the output being spent [9](#0-8) .
- `wallet.handlePrivatePaymentChains()` (invoked from a paired device/hub message) validates each chain in the array via `network.handleOnlinePrivatePayment`, again with no per-output lock [10](#0-9) .

Because the "is duplicate" SELECT in `private_payment.js:62-76` and the final INSERT/UPDATE in `divisible_asset.js`/`indivisible_asset.js` happen on **separate connections without a shared mutex**, both concurrent invocations can pass the duplicate check before either has committed its INSERT, and both can then commit a spend of the same private output. This is a direct code-level analog of the CVE's bug class (kernel checks state then uses stale state before the corresponding action is committed) applied to ocore's private-payment acceptance path, which is reachable from any private-payment counterparty or paired device sending (or replaying) a private-payment chain, matching the allowed threat surface (private payment chains).

### Impact Explanation
Successful exploitation lets an attacker with control of one endpoint of a private-payment relationship (a payer, or a device that resends previously issued private chains) get two conflicting spends of the same private output accepted locally by the recipient's wallet/node before serialization catches up. Since acceptance of `is_unique`/`is_spent` state for private (non-public) outputs is not policed by the public DAG consensus mechanism (private asset spends are only verified by the parties who hold the private data, per `objAsset.is_private` handling throughout `validation.js`), a successful double-acceptance can lead to the same private funds being recorded as received twice, or a payee's node disagreeing about whether an output is spent — a form of double-spend of a stable/pending output and/or fund-accounting corruption for private assets.

### Likelihood Explanation
Exploitation requires triggering two overlapping `validateAndSavePrivatePaymentChain` calls for the same (unit, message_index[, output_index]) key before the first transaction commits. This is plausible because:
- `handleSavedPrivatePayments()` explicitly processes rows with `async.each` (parallel), so multiple unhandled private payment rows referencing the same or related outputs can be dispatched to the private-payment validators concurrently.
- A malicious sender/paired device can deliberately resend the same or a conflicting private chain via `handlePrivatePaymentChains`/`handleOnlinePrivatePayment` in quick succession (network jitter or intentional flooding) to widen the race window between the SELECT-based duplicate check and the eventual commit.
- No `mutex.lock` keyed by unit/output (analogous to the `["write"]` or `arrAuthorAddresses` locks used elsewhere in the codebase) exists in this specific path, unlike the general unit-validation/save path.

Because it depends on timing and requires two chains to be crafted/sent, it is not trivially reliable, but it doesn't need any privileged access — any private-payment counterparty or paired device can attempt it, which supports a Medium severity rating consistent with the CVSS in the report.

### Recommendation
Serialize the check-then-use sequence: wrap the entire duplicate-check + validate + insert flow in `private_payment.js`'s `validateAndSavePrivatePaymentChain()` under a `mutex.lock()` keyed by a stable identifier of the target output (e.g., `["private_output", unit, message_index, output_index]`), similar to the `mutex.lock(arrAuthorAddresses, ...)` pattern used in `validation.js` or the `mutex.lock(["private_write"], ...)` already used for double-spend acceptance in `validation.js` `checkInputDoubleSpend()` [11](#0-10) . Additionally, change `network.handleSavedPrivatePayments()` to process rows for potentially conflicting outputs serially (or key the lock per output) instead of unconditionally in parallel via `async.each` [12](#0-11) .

### Proof of Concept
1. Attacker (private-payment sender) crafts two private-payment chains, `chainA` and `chainB`, that both ultimately spend the same private output `O` (same `unit`/`message_index`/`output_index`), e.g., by resending a legitimate chain a second time with a manipulated cosigner/recipient address, or by exploiting parallel delivery of a chain through both hub-forwarded and direct-peer paths.
2. Attacker sends `chainA` and `chainB` to the victim's wallet in rapid succession (e.g., once directly, once via a paired-device replay through `handlePrivatePaymentChains`).
3. `network.handleOnlinePrivatePayment()` for each chain invokes `privatePayment.validateAndSavePrivatePaymentChain()` on its own pooled connection.
4. Both connections execute the duplicate-check `SELECT` (private_payment.js:70-76) before either has committed its `INSERT ... INTO inputs` (indivisible_asset.js:253-288 / divisible_asset.js:57-70), each seeing `rows.length === 0` for output `O` (or not detecting it as spent yet).
5. Both transactions proceed to validate spend proofs independently and COMMIT, resulting in output `O` being recorded as spent by two different (possibly conflicting) inputs/private chains, corrupting the recipient's private-asset balance and later reconciliation between the parties.

### Citations

**File:** validation.js (L357-358)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
		
```

**File:** validation.js (L2283-2295)
```javascript
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
```

**File:** private_payment.js (L45-76)
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
```

**File:** divisible_asset.js (L56-70)
```javascript
				var is_unique = bStable ? 1 : null; // unstable still have chances to become nonserial therefore nonunique
				conn.addQuery(arrQueries, "INSERT INTO inputs \n\
						(unit, message_index, input_index, type, \n\
						src_unit, src_message_index, src_output_index, \
						serial_number, amount, \n\
						asset, is_unique, address) VALUES(?,?,?,?,?,?,?,?,?,?,?,"+(address_sql || conn.escape(address))+")",
					[unit, message_index, j, type, 
					 src_unit, src_message_index, src_output_index, 
					 input.serial_number, input.amount, 
					 payload.asset, is_unique]);
				if (type === "transfer"){
					conn.addQuery(arrQueries, 
						"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
						[src_unit, src_message_index, src_output_index]);
				}
```

**File:** divisible_asset.js (L118-142)
```javascript
							conn.query(
								"SELECT address, amount, blinding FROM outputs WHERE unit=? AND message_index=? AND output_index=? AND asset=?",
								[input.unit, input.message_index, input.output_index, payload.asset],
								function(rows){
									if (rows.length !== 1)
										return cb("not 1 row when selecting src output");
									var src_output = rows[0];
									try {
										var spend_proof = objectHash.getBase64Hash({
											asset: payload.asset,
											unit: input.unit,
											message_index: input.message_index,
											output_index: input.output_index,
											address: src_output.address,
											amount: src_output.amount,
											blinding: src_output.blinding
										});
									}
									catch (e) {
										return cb("failed to calc transfer spend proof: " + e.message);
									}
									arrSpendProofs.push({address: src_output.address, spend_proof: spend_proof});
									cb();
								}
							);
```

**File:** indivisible_asset.js (L22-52)
```javascript
	function validateSpendProof(spend_proof, cb){
		profiler.start();
		conn.query(
			"SELECT spend_proof, address FROM spend_proofs WHERE unit=? AND message_index=?", 
			[objPrivateElement.unit, objPrivateElement.message_index], 
			function(rows){
				profiler.stop('spend_proof');
				if (rows.length !== 1)
					return cb("expected 1 spend proof, found "+rows.length);
				var stored_spend_proof = rows[0].spend_proof;
				var spend_proof_address = rows[0].address;
				if (stored_spend_proof !== spend_proof)
					return cb("spend proof doesn't match");
				if (objPrevPrivateElement && objPrevPrivateElement.output.address !== spend_proof_address)
					return cb("spend proof address does not match src output");
				if (input.address && input.address !== spend_proof_address)
					return cb("spend proof address does not match issuer address");
				cb();
			}
		);
	}
	
	function validateSourceOutput(cb){
		if (conf.bLight)
			return cb(); // already validated the linkproof
		profiler.start();
		graph.determineIfIncluded(conn, input.unit, [objPrivateElement.unit], function(bIncluded){
			profiler.stop('determineIfIncluded');
			bIncluded ? cb() : cb("input unit not included");
		});
	}
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

**File:** network.js (L2459-2510)
```javascript
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
					
```

**File:** wallet.js (L1020-1063)
```javascript
	async.eachSeries(
		arrChains,
		function(arrPrivateElements, cb){ // validate each chain individually
			var objHeadPrivateElement = arrPrivateElements[0];
			if (!!objHeadPrivateElement.payload.denomination !== ValidationUtils.isNonnegativeInteger(objHeadPrivateElement.output_index))
				return cb("divisibility doesn't match presence of output_index");
			var output_index = objHeadPrivateElement.payload.denomination ? objHeadPrivateElement.output_index : -1;
			try {
				var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
			}
			catch (e) {
				return cb("head priv element hash failed " + e.toString());
			}
			var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+output_index;
			assocValidatedByKey[key] = false;
			network.handleOnlinePrivatePayment(ws, arrPrivateElements, true, {
				ifError: function(error){
					console.log("handleOnlinePrivatePayment error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifValidationError: function(unit, error){
					console.log("handleOnlinePrivatePayment validation error: "+error);
					cb("an error"); // do not leak error message to the hub
				},
				ifAccepted: function(unit){
					console.log("handleOnlinePrivatePayment accepted");
					assocValidatedByKey[key] = true;
					cb(); // do not leak unit info to the hub
				},
				// this is the most likely outcome for light clients
				ifQueued: function(){
					console.log("handleOnlinePrivatePayment queued, will wait for "+key);
					eventBus.once(key, function(bValid){
						if (!bValid)
							return cancelAllKeys();
						assocValidatedByKey[key] = true;
						if (bParsingComplete)
							checkIfAllValidated();
						else
							console.log('parsing incomplete yet');
					});
					cb();
				}
			});
```
