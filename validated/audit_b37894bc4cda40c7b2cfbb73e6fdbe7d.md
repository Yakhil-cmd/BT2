## Analysis

This maps onto the `mirage-xen` bug class well: a state-mutating operation (a DB write meant to enforce that a resource cannot be released/finalized twice) is fired without ever checking whether it actually took effect, and the caller unconditionally reports success anyway — exactly like `stub_gntshr_end_access` ignoring Mini-OS's "not yet unshared" return code and telling OCaml the unshare succeeded regardless.

### Title
Private payment chain output reveal ignores UPDATE result, allowing a validated-but-not-recorded double reveal of a shared output - ([File: indivisible_asset.js])

### Summary
`validateAndSavePrivatePaymentChain` in [1](#0-0)  builds a batch of SQL statements to persist a private (indivisible-asset) payment chain. For the output that is being revealed, it issues an `UPDATE outputs SET is_serial=?, is_spent=?, address=?, blinding=? WHERE unit=? AND message_index=? AND output_index=? AND is_spent=0`, guarded by `AND is_spent=0` to prevent re-revealing/re-spending an output that a conflicting chain already claimed [2](#0-1) . The number of affected rows from this guarded `UPDATE` is never inspected — the whole batch is simply run with `async.series(arrQueries, function(){ ...; callbacks.ifOk(); })` [3](#0-2) , so `ifOk()` fires unconditionally whether or not the guard actually blocked the write.

### Finding Description
The `is_spent=0` guard is the only mechanism preventing two different, individually-well-formed private chains from both successfully "revealing" (assigning `address`/`blinding` and flipping `is_serial`/`is_spent`) the same underlying output. Earlier validation steps (`validatePrivatePayment`, `validateSpendProof`) check the spend proof against what was pre-committed in the `spend_proofs` table [4](#0-3) , but that does not prevent a malicious issuer/sender from constructing two divergent private chains that pass this per-chain check independently (e.g., sent to two different cosigners/recipients of a multi-party shared address, or replayed to two different peers) and each reference the same head output. When the second chain's validation runs, its guarded `UPDATE ... AND is_spent=0` becomes a no-op because the first chain already set `is_spent=1`, yet the code has no branch to detect "0 rows affected" — it proceeds straight to `callbacks.ifOk()` exactly as in the successful case.

This is structurally identical to the reported bug class: a lower-level operation that can legitimately fail/no-op to protect a shared resource has its result silently discarded, so the higher-level caller (and ultimately the recipient's wallet via `getSavingCallbacks`/`ifOk` in [5](#0-4)  and the network handler in [6](#0-5) ) believes the private payment was fully and correctly persisted when the database state disagrees.

### Impact Explanation
Two counterparties (or a cosigner and the payee on a shared address) can each receive an `ifOk`/"accepted" signal for what they believe is their own valid, uniquely-spent private output, while only one of them is actually recorded as the legitimate holder of that output in the `outputs` table. This produces disagreement between local wallet state and DB state for the losing party (their balance/received-funds display is inconsistent with what is actually spendable), and enables the sender to present a spent/void private-payment claim as accepted to a party who did not actually receive it — a fund-loss/inconsistent-ledger scenario within the private payment chain trust model.

### Likelihood Explanation
Triggering this requires an unprivileged private-payment counterparty (the asset issuer/sender in a private, indivisible-asset chain) to construct two internally valid but mutually conflicting private chains for the same source output and deliver them to two different recipients/cosigners — something fully within reach of a malicious sender in normal wallet-to-wallet or shared-address private payment flows, no privileged, network, or node-level access needed.

### Recommendation
After executing the guarded `UPDATE ... AND is_spent=0`, check the affected-row count (`db`-driver equivalent of `affectedRows`) and route to `callbacks.ifError(...)` (not `ifOk()`) when the guard actually blocked the write, mirroring how `mirage-xen` was fixed by propagating the true result of the "end access" operation instead of assuming success.

### Proof of Concept
1. Sender creates output O in a private indivisible-asset unit.
2. Sender builds private chain A revealing O to recipient X, and a conflicting private chain B revealing the same O to recipient/cosigner Y, both individually satisfying `validatePrivatePayment`'s spend-proof checks.
3. Chain A is submitted and processed first: `UPDATE ... WHERE ... AND is_spent=0` matches and sets `is_spent=1`; `ifOk()` fires, X's wallet marks the payment accepted.
4. Chain B is submitted afterward: the same guarded `UPDATE` now matches 0 rows (since `is_spent` is already 1) and is a no-op, but because the affected-row count is never checked, `async.series` still completes normally and `ifOk()` fires — Y's wallet also marks the payment as accepted, despite never having their claim actually recorded in `outputs`.

### Citations

**File:** indivisible_asset.js (L20-42)
```javascript
function validatePrivatePayment(conn, objPrivateElement, objPrevPrivateElement, callbacks){
		
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
```

**File:** indivisible_asset.js (L239-297)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	parsePrivatePaymentChain(conn, arrPrivateElements, {
		ifError: callbacks.ifError,
		ifOk: function(bAllStable){
			console.log("saving private chain "+JSON.stringify(arrPrivateElements));
			profiler.start();
			var arrQueries = [];
			for (var i=0; i<arrPrivateElements.length; i++){
				var objPrivateElement = arrPrivateElements[i];
				var payload = objPrivateElement.payload;
				var input_address = objPrivateElement.input_address;
				var input = payload.inputs[0];
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
			}
		//	console.log("queries: "+JSON.stringify(arrQueries));
			async.series(arrQueries, function(){
				profiler.stop('save');
				callbacks.ifOk();
			});
		}
	});
}
```

**File:** indivisible_asset.js (L856-862)
```javascript
				ifOk: function(objValidationState, validation_unlock){
					console.log("Private OK "+objValidationState.sequence);
					if (objValidationState.sequence !== 'good'){
						validation_unlock();
						combined_unlock();
						return callbacks.ifError("Indivisible asset bad sequence "+objValidationState.sequence);
					}
```

**File:** network.js (L2415-2428)
```javascript
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
```
