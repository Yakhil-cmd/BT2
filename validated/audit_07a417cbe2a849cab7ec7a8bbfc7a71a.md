## Analog Found

### Title
Permanent deletion of unrecoverable private payment chain data on validation error causes permanent freezing of legitimately-owned private asset funds - ([File: network.js])

### Summary
The reported bug class is: a "cancel"/error-handling code path that unconditionally and irreversibly deletes state needed to later claim funds, even though the underlying value (unclaimed epochs / remaining rewards) is still legitimately owed. The `ocore` analog is in the private-payment (indivisible/divisible hidden-blinded asset) delivery pipeline: `handleSavedPrivatePayments()` / `handleOnlinePrivatePayment()` in `network.js` permanently `DELETE`s the only copy of a received private-payment chain (`unhandled_private_payments`) as soon as `validateAndSavePrivatePaymentChain()` reports any error, with no distinction between "permanently invalid" and "not yet processable" errors, and no way to recover the blinding/address data afterwards.

### Finding Description
Private (hidden) payments carry blinding factors and addresses that are known **only** through the private element chain that is sent peer-to-peer/via hub; this data cannot be reconstructed from the public DAG. When a chain is received it is queued in `unhandled_private_payments` [1](#0-0) , and later processed by `handleSavedPrivatePayments()`.

On any error from `privatePayment.validateAndSavePrivatePaymentChain()` — including a thrown exception while just computing the payload hash — the code calls `deleteHandledPrivateChain()`, which unconditionally issues `DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?` and never re-queues or persists the chain elsewhere: [2](#0-1) [3](#0-2) 

Notably, the exception-catch branch (`json_payload_hash` computation failing) calls `deleteHandledPrivateChain` but has **no `return`**, so execution falls through to use the now-undefined `json_payload_hash`/`key` and still invokes `validateAndSavePrivatePaymentChain` a second time on the already-deleted record — illustrating how casually the deletion is triggered on any failure path, not just a definitively-invalid chain: [4](#0-3) 

The same rigor-mismatch appears in the light-client link-proof path: if `checkThatEachChainElementIncludesThePrevious` returns `false` (not linked) for any reason, `updateLinkProofsOfPrivateChain` immediately calls `deleteHandledPrivateChain`, again permanently discarding the only copy of the chain: [5](#0-4) 

Unlike public payments (recoverable by re-requesting the DAG), a private payment's address/blinding/spend-proof material for hidden outputs exists only in these chain records. `validateAndSavePrivatePaymentChain()` in `private_payment.js` can return `ifError` for many reasons that are not necessarily "this is fraudulent and must never be retried" (e.g., asset-state races, malformed-but-recoverable intermediate elements, temporary inconsistencies in `initPrivatePaymentValidationState`), yet the caller always deletes on `ifError`: [6](#0-5) 

Because the sender/counterparty of a private payment (an unprivileged party who composes and transmits the private element chain) controls the exact shape/timing of what is sent, a counterparty can craft or time a chain such that it initially triggers one of these error branches (e.g., a hidden output whose `duplicate` detection or asset lookup races against local processing), causing the victim's node to `DELETE` the only record of the private chain forever — while the underlying stable, spent-to-the-victim output remains locked on the DAG, unusable because the address/blinding proof needed to spend it has been discarded and cannot be recomputed by the recipient.

### Impact Explanation
This is analogous to `cancelPromotion`'s "too rigorous" deletion: an error/cancel handler destroys state that is required to later claim already-owed value, with no partial/soft-delete or retry path. Here the destroyed state is the blinding/address material for a private (indivisible or divisible) asset output that has already been paid to the victim's address on the DAG. Losing it means the victim can never construct a valid spend for that output — i.e., a concrete and permanent freezing of funds that rightfully belong to the recipient, reachable purely through a private-payment counterparty's message content/timing, without requiring any hub/node compromise.

### Likelihood Explanation
Any private-payment sender (the counterparty in a private asset trade — an unprivileged, ordinary role reachable by anyone using private assets) can trigger this by sending a private element chain whose processing hits one of the many `ifError` branches inside `validateAndSavePrivatePaymentChain`/`initPrivatePaymentValidationState`, or a link-proof check that (transiently or adversarially) fails, at which point `network.js` deletes the sole copy of the chain unconditionally.

### Recommendation
Do not treat every validation failure as a permanent, unrecoverable deletion:
- Distinguish definitively-invalid chains (bad signature/hash, provable double spend) from transient/ambiguous failures (`ifWaitingForChain`-like states, asset lookup races, link-proof `null`/inconclusive results), and only delete for the former.
- For ambiguous failures, keep the record (optionally increment a retry counter/backoff) rather than issuing `DELETE FROM unhandled_private_payments`, so the recipient retains a chance to recover/re-validate before the only copy of the blinding data is lost.
- Fix the missing `return` after the `catch` block in `handleSavedPrivatePayments` so a hash-computation failure does not fall through into a second, inconsistent use of the deleted record.

### Proof of Concept
1. Recipient (victim) node receives a private payment chain via `handleOnlinePrivatePayment`, which is queued into `unhandled_private_payments`.
2. `handleSavedPrivatePayments()` picks it up and calls `privatePayment.validateAndSavePrivatePaymentChain()`.
3. The sender times/crafts the chain (or an unrelated race in asset-info loading / duplicate detection) such that validation returns `ifError` for a reason that is not a genuine invalidity of the chain data itself.
4. `network.js` immediately calls `deleteHandledPrivateChain(unit, message_index, output_index, cb)`, permanently removing the only stored copy of the address/blinding/spend-proof data for that hidden output.
5. The underlying output remains stable and spent-to-victim on the DAG, but the victim's wallet can never reconstruct the blinding data needed to spend it — the funds are permanently frozen, mirroring the "cancelPromotion deletes state that is still needed to claim owed value" pattern from the source report.

### Citations

**File:** network.js (L2390-2402)
```javascript
	var savePrivatePayment = function(cb){
		// we may receive the same unit and message index but different output indexes if recipient and cosigner are on the same device.
		// in this case, we also receive the same (unit, message_index, output_index) twice - as cosigner and as recipient.  That's why IGNORE.
		db.query(
			"INSERT "+db.getIgnore()+" INTO unhandled_private_payments (unit, message_index, output_index, json, peer) VALUES (?,?,?,?,?)", 
			[unit, message_index, output_index, JSON.stringify(arrPrivateElements), bViaHub ? '' : ws.peer], // forget peer if received via hub
			function(){
				callbacks.ifQueued();
				if (cb)
					cb();
			}
		);
	};
```

**File:** network.js (L2467-2496)
```javascript
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
```

**File:** network.js (L2523-2527)
```javascript
function deleteHandledPrivateChain(unit, message_index, output_index, cb){
	db.query("DELETE FROM unhandled_private_payments WHERE unit=? AND message_index=? AND output_index=?", [unit, message_index, output_index], function(){
		cb();
	});
}
```

**File:** network.js (L2701-2711)
```javascript
	checkThatEachChainElementIncludesThePrevious(arrPrivateElements, function(bLinked){
		if (bLinked === null)
			return onFailure();
		if (!bLinked)
			return deleteHandledPrivateChain(unit, message_index, output_index, onFailure);
		// the result cannot depend on output_index
		db.query("UPDATE unhandled_private_payments SET linked=1 WHERE unit=? AND message_index=?", [unit, message_index], function(){
			onSuccess();
		});
	});
}
```

**File:** private_payment.js (L35-60)
```javascript
	var validateAndSave = function(){
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (objAsset.is_private !== 1)
				return callbacks.ifError("asset is not private");
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			if (!!objAsset.fixed_denominations !== ("output" in headElement))
				return callbacks.ifError("divisible asset must not have output field, indivisible must");
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
```
