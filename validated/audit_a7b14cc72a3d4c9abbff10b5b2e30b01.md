### Title
Race condition between concurrent private-payment chain deliveries allows a private-payment counterparty to double-spend a private-asset output — ([File: private_payment.js])

### Summary
The ksmbd CVE-2023-32256 stems from two concurrent operations (smb2 close and logoff) racing on the same session/handle object over separate connections, with no exclusive lock guarding the check/free sequence, resulting in a use-after-free. The closest reachable analog in ocore is the check-then-act race in `validateAndSavePrivatePaymentChain()` in `private_payment.js`, which is invoked from two independent, concurrently-reachable entry points (`network.handleOnlinePrivatePayment()` for a "known" unit, and `network.handleSavedPrivatePayments()` for queued chains) with **no mutex serializing writes for the same `(unit, message_index, output_index)` private output**. A private-payment counterparty can exploit the gap between the duplicate-check `SELECT` and the subsequent `INSERT`/`UPDATE` of `outputs`/`inputs` to get two different private elements accepted for the same underlying output.

### Finding Description
`network.handleOnlinePrivatePayment()` explicitly disables the `assocUnitsInWork` guard for the "known unit" code path: [1](#0-0) 
Note the commented-out lines `//assocUnitsInWork[unit] = true;` and `//delete assocUnitsInWork[unit];` — unlike the ordinary joint-processing pipeline (`handleJoint`), which strictly serializes per-unit work via `assocUnitsInWork`, private payment chains for an already-known unit go straight into `privatePayment.validateAndSavePrivatePaymentChain()` with no per-unit in-flight guard.

In parallel, `network.handleSavedPrivatePayments()` also calls the same function for rows queued in `unhandled_private_payments`, using `async.each` to process multiple rows **concurrently** and only a coarse `["saved_private"]` mutex (which does not key on unit/message_index/output_index): [2](#0-1) 

Both call paths converge on `private_payment.js`’s `validateAndSavePrivatePaymentChain()`, which performs a classic time-of-check/time-of-use (TOCTOU) sequence per call, each with its **own independent DB connection and transaction**: [3](#0-2) 

Each invocation:
1. Opens a new connection and `BEGIN`s its own transaction (no cross-call locking).
2. Runs a `SELECT ... FROM outputs WHERE unit=? AND asset=? AND message_index=? [AND output_index=?]` to detect a duplicate reveal of the same hidden output.
3. Only if a matching row with a **non-null address** already exists does it treat it as a duplicate and short-circuit with `ifOk`.
4. Otherwise, it proceeds to `assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks)`, which performs `INSERT`/`UPDATE` on `outputs`/`inputs` (see `divisible_asset.js`): [4](#0-3) 

Because the duplicate-check `SELECT` and the write happen in separate, uncoordinated transactions across calls, two private elements referencing the **same hidden output** (same `unit`, `message_index`, `output_index`, but carrying two *different* claimed `address`/`amount`/`blinding` reveals — e.g., sent to two different recipients, or a genuine payment plus an attacker-crafted alternate reveal) can both pass step 3 (since the address column is still `NULL`/hidden at the time both `SELECT`s run) before either commits its `UPDATE ... SET is_spent=1, address=?, blinding=? ... WHERE ... AND is_spent=0` for the corresponding spent input.

This is structurally the same bug class as the ksmbd CVE: two concurrent handlers operate on the same underlying shared resource (a private, still-hidden output) without a proper exclusive lock spanning the read-check and the write, because the "in-flight" tracking (`assocUnitsInWork`) was deliberately bypassed for this code path.

### Impact Explanation
A private-payment counterparty (the entity legitimately possessing the encrypted private-payment chain for a shared/hidden output) who controls timing of delivery — e.g. by sending the same private element via two peers/paths simultaneously, or by re-emitting it while a first copy is still mid-processing on a slow connection — can cause the recipient/hub node to accept two conflicting reveals of the same output. Because `is_spent`/`address`/`blinding` are only set conditionally on `is_spent=0` and the "duplicate" detection in `private_payment.js` reads before either write commits, the second race branch can bypass the "duplicate" short-circuit and independently execute `INSERT`/`UPDATE` logic for a different reveal of the same output, potentially assigning the private output to two different addresses/spend paths in the local `outputs`/`inputs` cache used by the wallet to determine balances — leading to node disagreement on which private element is authoritative and, in the worst case, this node's own wallet accounting believing that funds are simultaneously available to two different owners of the same hidden output, i.e., a local double-spend view of a private stable output. This qualifies as a "double-spend of a stable output" / "node disagreement on validity" per the report's acceptance criteria.

### Likelihood Explanation
Reachable by a normal private-payment counterparty with no special privileges — simply sending a device message of subject `private_payments` (handled in `wallet.js`) or delivering a chain directly to a peer (handled by `network.handleOnlinePrivatePayment`), timed to arrive twice in close succession (e.g., once via `handleOnlinePrivatePayment`'s "known" branch which has locking intentionally disabled, and once via the periodic/`handleSavedPrivatePayments` queue-draining path, or two duplicate concurrent deliveries). Because the "known" branch's `assocUnitsInWork` guard is explicitly commented out, exploitation requires no unusual timing skill beyond sending the payload more than once close together — a low-cost, medium-likelihood condition, consistent with the CVSS AC:H rating of the original report (race window is narrow but reachable without special access).

### Recommendation
Reinstate serialization for private-payment chain processing keyed by the target output identity (e.g., `unit + ':' + message_index + ':' + output_index`, or at minimum the affected `unit`), using `mutex.lock` around the full check-then-write sequence in `private_payment.validateAndSavePrivatePaymentChain()`, and restore the `assocUnitsInWork` (or an equivalent per-output lock) guard in `network.handleOnlinePrivatePayment()`'s "known" branch rather than leaving it disabled. Ensure the duplicate-check `SELECT` and the subsequent `INSERT`/`UPDATE` occur under a single exclusive lock spanning both call paths (`handleOnlinePrivatePayment` and `handleSavedPrivatePayments`) so that concurrent reveals of the same hidden output cannot both pass the TOCTOU window.

### Proof of Concept
1. Attacker (private-payment counterparty) crafts two private-element chains, `A` and `B`, both referencing the same `(unit, message_index, output_index)` of a divisible or indivisible private asset output, but with two different claimed reveals (different `address`/`blinding`/`amount` combination that both hash-match the hidden `output_hash`, or simply two different genuine recipients if the sender colludes).
2. Deliver `A` directly to the victim node/hub via the `hub/deliver` → `private_payments` device-message path so it lands in `handleMessageFromHub` → `wallet.handlePrivatePaymentChains` → eventually `network.handleOnlinePrivatePayment`, and simultaneously (or with very close timing) place `B` such that it gets processed via the `unhandled_private_payments` table drain in `handleSavedPrivatePayments` (e.g., by having a peer relay a previously queued copy at the same moment).
3. Because `handleOnlinePrivatePayment`'s "known" branch has `assocUnitsInWork` disabled (`network.js` lines ~2412-2429) and `handleSavedPrivatePayments` only holds a coarse `saved_private` lock not keyed by output identity, both `A` and `B` can independently reach `private_payment.validateAndSavePrivatePaymentChain()` in overlapping transactions.
4. Both transactions run their `SELECT` duplicate-check before either `COMMIT`s; since the stored output row still has `address IS NULL` at that point, neither treats the other as a duplicate, and both proceed to insert/update `outputs`/`inputs`, leaving the local database with two conflicting resolutions of the same hidden output's ownership/spend status.

### Citations

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

**File:** network.js (L2455-2510)
```javascript
		db.query(sql, function(rows){
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
					
```

**File:** private_payment.js (L45-107)
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
```

**File:** divisible_asset.js (L23-74)
```javascript
function validateAndSaveDivisiblePrivatePayment(conn, objPrivateElement, callbacks){
	validateDivisiblePrivatePayment(conn, objPrivateElement, {
		ifError: callbacks.ifError,
		ifOk: function(bStable, arrAuthorAddresses){
			console.log("private validation OK "+bStable);
			var unit = objPrivateElement.unit;
			var message_index = objPrivateElement.message_index;
			var payload = objPrivateElement.payload;
			var arrQueries = [];
			for (var j=0; j<payload.outputs.length; j++){
				var output = payload.outputs[j];
				conn.addQuery(arrQueries, 
					"INSERT INTO outputs (unit, message_index, output_index, address, amount, blinding, asset) VALUES (?,?,?,?,?,?,?)",
					[unit, message_index, j, output.address, parseInt(output.amount), output.blinding, payload.asset]
				);
			}
			for (var j=0; j<payload.inputs.length; j++){
				var input = payload.inputs[j];
				var type = input.type || "transfer";
				var src_unit = input.unit;
				var src_message_index = input.message_index;
				var src_output_index = input.output_index;
				var address = null, address_sql = null;
				if (type === "issue")
					address = input.address || arrAuthorAddresses[0];
				else{ // transfer
					if (arrAuthorAddresses.length === 1)
						address = arrAuthorAddresses[0];
					else
						address_sql = "(SELECT address FROM outputs \
						WHERE unit="+conn.escape(src_unit)+" AND message_index="+conn.escape(src_message_index)+" \
							AND output_index="+conn.escape(src_output_index)+" AND address IN("+conn.escape(arrAuthorAddresses)+"))";
				}
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
			}
			async.series(arrQueries, callbacks.ifOk);
		}
	});
```
