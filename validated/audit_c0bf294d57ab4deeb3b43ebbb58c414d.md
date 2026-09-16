### Title
Race condition in private payment chain handling allows double-processing of the same private chain without serialization - ([File: network.js])

### Summary
`handleOnlinePrivatePayment()` in `network.js` performs an async, un-locked "is this unit known" check via `joint_storage.checkIfNewUnit()` and then, based on the result, calls `privatePayment.validateAndSavePrivatePaymentChain()` directly with **no mutex serializing concurrent invocations for the same chain**. This mirrors the CVE-2026-43023 root cause: a state check is performed without holding a lock, so two concurrent calls can both pass the check and both proceed to mutate shared state, leading to double-processing.

### Finding Description
`handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks)` explicitly performs its "known unit" check without any locking, and the code even shows the original `assocUnitsInWork[unit]` guard commented out: [1](#0-0) 

```
joint_storage.checkIfNewUnit(unit, {
    ifKnown: function(){
        //assocUnitsInWork[unit] = true;
        privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
            ifOk: function(){
                //delete assocUnitsInWork[unit];
                ...
```

`joint_storage.checkIfNewUnit()` itself is asynchronous (it may hit the DB) and holds no mutex: [2](#0-1) 

Once the `ifKnown` branch is taken, `privatePayment.validateAndSavePrivatePaymentChain()` is invoked. This function opens its own dedicated DB connection/transaction per call, queries for a pre-existing (duplicate) output, and if none is visible **within its own uncommitted transaction**, proceeds to insert: [3](#0-2) [4](#0-3) 

Because each concurrent call to `handleOnlinePrivatePayment()` for the *same* private chain (e.g., received simultaneously through the hub and directly from a peer, or from two cosigner devices) takes its own connection and its own `BEGIN`/duplicate-check/`COMMIT` cycle, neither transaction can see the other's uncommitted insert. Both can pass the duplicate check and both proceed to `assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, ...)`, which performs the actual `INSERT INTO outputs`/`INSERT INTO inputs` and marks source outputs `is_spent=1`: [5](#0-4) 

This is the exact bug-class match to sco_sock_connect(): a "check state, then act" sequence with an async gap and no lock serializing concurrent callers, allowing state to be mutated twice from what should be a single-shot operation. In the kernel bug this produced a UAF/double free on a socket; here it allows the same private payment chain (private asset transfer, which relies on hidden/off-DAG state validated only by this code path) to be recorded/spent twice by racing concurrent submissions, in contrast to the sibling code paths (`composer.js`, `divisible_asset.js`, `indivisible_asset.js` `getSavingCallbacks`) that correctly wrap validate+save in `mutex.lock('handleJoint')`: [6](#0-5) 

By contrast, `handleSavedPrivatePayments()` (the *queued* processing path) does correctly serialize with `mutex.lock(["saved_private"])`, showing this path's intended design, which `handleOnlinePrivatePayment`'s `ifKnown` branch does not follow: [7](#0-6) 

### Impact Explanation
Private assets (`is_private=1`) are validated/settled entirely through this database-driven duplicate-check-then-insert flow rather than through the normal DAG-unit `handleJoint`/`mutex.lock('handleJoint')` serialization. A successful race lets an attacker who controls or colludes with a counterparty in a private payment (a normal, unprivileged private-payment counterparty as explicitly in scope) submit the same private chain concurrently via two channels (hub-relayed and direct peer, or duplicate submission from two connections), causing the private outputs/inputs to be inserted more than once or the source output marked `is_spent` inconsistently across racing transactions. This can result in inconsistent/duplicated private balance state or a private output being spendable more than once (double-spend of a private-asset output), i.e. unauthorized spending / supply-consistency violation for private assets, and disagreement between the two racing transactions' committed states.

### Likelihood Explanation
The trigger requires only that an attacker/counterparty deliver the identical `private_payment` message content (chain) at nearly the same time via two accepted delivery paths (`bViaHub` true/false, i.e., hub-relayed vs. direct peer WS) which `handleOnlinePrivatePayment()` and `wallet.js`'s `handlePrivatePaymentChains()` both accept from any paired/correspondent device without additional locking on this specific path. No special privilege beyond being a private-payment counterparty is required, and the commented-out `assocUnitsInWork` guard demonstrates the protection was deliberately removed/never replaced with an equivalent lock for this branch.

### Recommendation
Serialize `handleOnlinePrivatePayment()`'s `ifKnown` branch (and generally all entry points into `privatePayment.validateAndSavePrivatePaymentChain`) with a `mutex.lock([...])` keyed by the private chain's identifying key (e.g., unit + message_index + output_index or `json_payload_hash`), matching the pattern already used by `handleSavedPrivatePayments()` (`mutex.lock(["saved_private"])`) and by the public-payment saving paths (`mutex.lock('handleJoint')` in `composer.js`/`divisible_asset.js`/`indivisible_asset.js`). Reinstate an in-work guard analogous to `assocUnitsInWork` for private chains so concurrent duplicate submissions are rejected/queued rather than racing through independent DB transactions.

### Proof of Concept
1. Craft a valid private payment chain `arrPrivateElements` for a private asset whose head unit is already known to the target node (`checkIfNewUnit` → `ifKnown`).
2. From two separate connections (e.g., one direct peer WS call to `network.handleOnlinePrivatePayment(ws1, arrPrivateElements, false, cb1)` and one hub-relayed call reaching the same function with `bViaHub=true`), submit the identical chain simultaneously.
3. Both calls pass `checkIfNewUnit`'s `ifKnown` check before either has committed, and both call `privatePayment.validateAndSavePrivatePaymentChain`, each opening its own connection/transaction and passing the duplicate-output check (`private_payment.js` lines 62-103) because neither transaction sees the other's uncommitted insert.
4. Both transactions proceed to insert outputs/inputs and mark the source output `is_spent=1`, resulting in the private chain being recorded/spent twice.

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

**File:** network.js (L2444-2451)
```javascript
function handleSavedPrivatePayments(unit){
	//if (unit && assocUnitsInWork[unit])
	//    return;
	if (!my_device_address) return; // skip if we don't have a wallet
	if (!unit && mutex.isAnyOfKeysLocked(["private_chains"])) // we are still downloading the history (light)
		return console.log("skipping handleSavedPrivatePayments because history download is still under way");
	var lock = unit ? mutex.lock : mutex.lockOrSkip;
	lock(["saved_private"], function(unlock){
```

**File:** joint_storage.js (L21-39)
```javascript
function checkIfNewUnit(unit, callbacks) {
	if (storage.isKnownUnit(unit))
		return callbacks.ifKnown();
	if (assocUnhandledUnits[unit])
		return callbacks.ifKnownUnverified();
	var error = assocKnownBadUnits[unit];
	if (error)
		return callbacks.ifKnownBad(error);
	db.query("SELECT sequence, main_chain_index FROM units WHERE unit=?", [unit], function(rows){
		if (rows.length > 0){
			var row = rows[0];
			if (row.sequence === 'final-bad' && row.main_chain_index !== null && row.main_chain_index < storage.getMinRetrievableMci()) // already stripped
				return callbacks.ifNew();
			storage.setUnitIsKnown(unit);
			return callbacks.ifKnown();
		}
		callbacks.ifNew();
	});
}
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

**File:** divisible_asset.js (L317-324)
```javascript
		ifOk: async function(objJoint, assocPrivatePayloads, composer_unlock){
			var objUnit = objJoint.unit;
			var unit = objUnit.unit;
			const validate_and_save_unlock = await mutex.lock('handleJoint');
			const combined_unlock = () => {
				validate_and_save_unlock();
				composer_unlock();
			};
```
