### Title
Missing concurrency guard on `handleOnlinePrivatePayment` allows concurrent double-processing of the same private-payment chain, causing duplicate output insertion / crash - (File: network.js)

### Summary
`network.js`'s `handleOnlinePrivatePayment()` is the entry point for private (hidden) payment chains delivered by a private-payment counterparty (directly or via hub/pairing device). The NATS analog is a peer sending repeated pre-auth `INFO` messages before the handshake/account-setup state machine finishes initializing, causing the server to act on partially-initialized state and crash. In ocore, the equivalent "setup not yet complete" window is the asynchronous DB transaction performed by `privatePayment.validateAndSavePrivatePaymentChain()` — and the guard that is supposed to prevent a second identical message from re-entering that window while the first is still in flight has been explicitly disabled.

### Finding Description
In `network.js`, `handleOnlinePrivatePayment()` calls into `joint_storage.checkIfNewUnit()` and, for a known unit, directly invokes `privatePayment.validateAndSavePrivatePaymentChain()`: [1](#0-0) 

The lines that would register the unit as "in work" and later clear it are commented out:
```
ifKnown: function(){
    //assocUnitsInWork[unit] = true;
    privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
        ifOk: function(){
            //delete assocUnitsInWork[unit];
``` [2](#0-1) 

`validateAndSavePrivatePaymentChain()` in `private_payment.js` performs its duplicate check and insert inside its own connection/transaction (`BEGIN` ... `SELECT` duplicate check ... `INSERT`/`COMMIT`): [3](#0-2) 

Because no in-memory lock (the disabled `assocUnitsInWork`) or `mutex.lock` serializes concurrent calls for the same `(unit, message_index, output_index)`, two copies of the same (or two independently delivered, e.g. via hub and directly from a peer, or twice from a paired device) private-payment chain arriving back-to-back can both pass the "check if duplicate" `SELECT` before either transaction commits, and both proceed into `divisibleAsset.validateAndSavePrivatePaymentChain()`/`indivisibleAsset.validateAndSavePrivatePaymentChain()`.

For divisible private assets, the output insert is a plain `INSERT INTO outputs (...) VALUES (...)` with no `INSERT OR IGNORE`/uniqueness protection: [4](#0-3) 
This allows the same private output to be recorded twice in the local `outputs` table under two competing transactions that both believed the output didn't exist yet.

The duplicate-detection code path itself also `throw`s on more than one matching row (`if (rows.length > 1) throw Error("more than one output ...")`), which is an unhandled exception thrown from inside an async DB callback — a state the code assumes "can't happen," but which the disabled `assocUnitsInWork` guard was there to prevent: [5](#0-4) 

This is structurally the same bug class as the NATS issue: a message that should be serialized against one in-flight "pre-completion" state (leafnode handshake/account setup vs. private-payment validate-and-save) is instead allowed to be processed again while the first instance's state transition (transaction commit) has not finished, because the guard that would reject/queue the repeat was removed/commented out.

### Impact Explanation
- Duplicate insertion of the same private output row corrupts the local ledger view of a divisible private asset, effectively double-crediting the recipient locally (a local supply-inflation of a private asset for that wallet), which can lead the wallet to believe it has more spendable private funds than it legitimately received and to construct/attempt to spend both records.
- The unguarded race can also trigger the `throw Error("more than one output ...")` path on a subsequent duplicate delivery, crashing the wallet/hub-connected node process that is handling private payments (unhandled exception in an async callback chain), a real availability impact for any node/wallet acting as a private-payment counterparty.
- This is reachable purely by a private-payment counterparty (or a paired device / hub relay of the same message) re-sending (or double-delivering) the same private-payment chain — no privileged, malicious-node, or protocol-authentication bypass is required.

### Likelihood Explanation
Likelihood is high for triggering the race window: `handleOnlinePrivatePayment` is called for every incoming `private_payment` justsaying and via `handlePrivatePaymentChains` (hub-forwarded chains) — both paths can be invoked concurrently for the same unit (e.g., once via hub, once via direct P2P from the recipient device, which the existing comment "we may receive the same unit and message index but different output indexes if recipient and cosigner are on the same device" acknowledges is a real and expected scenario). The `assocUnitsInWork` guard is present everywhere else in `network.js` (used 41 times) but is explicitly disabled only for this private-payment code path, indicating this is a code regression rather than a theoretical scenario.

### Recommendation
Re-enable the `assocUnitsInWork[unit]` guard (or use `mutex.lock` keyed by `unit`/`message_index`/`output_index`) around the call to `privatePayment.validateAndSavePrivatePaymentChain()` in `handleOnlinePrivatePayment()` so a second delivery of the same private-payment chain is queued/ignored while the first is still validating and saving, mirroring the pattern used elsewhere for joint validation (`mutex.lock('handleJoint')` in `divisible_asset.js`/`indivisible_asset.js`). Additionally, make the divisible-asset output insert idempotent (`INSERT OR IGNORE`, as already done in `indivisible_asset.js`) to eliminate the possibility of duplicate rows even if a race slips through.

### Proof of Concept
1. As a payer, send the same private-payment chain (`arrPrivateElements` for a given `unit`/`message_index`/`output_index`) to the victim wallet twice in rapid succession — once directly via P2P `private_payment` justsaying and once via the hub's `private_payments_chains` delivery (or simply re-send the identical direct message twice before the first has committed).
2. Both deliveries reach `handleOnlinePrivatePayment()` and, since `checkIfNewUnit` reports `ifKnown` for both (the underlying public unit is already known/confirmed), both proceed straight into `privatePayment.validateAndSavePrivatePaymentChain()` without any lock preventing concurrent execution.
3. Both instances execute the "check if duplicate" `SELECT` before either has committed its `INSERT`/`COMMIT`, so both see zero existing rows and both proceed to insert the output — resulting in two output records for what should be a single private payment (or, on a third delivery, causing an unhandled `throw Error("more than one output ...")` that crashes the process).

*(Note: full confirmation that no other higher-level in-memory de-duplication cache blocks the race for the direct-`ws` P2P path — as opposed to the hub-forwarded `handledChainsCache` in `wallet.js`, which only guards `handlePrivatePaymentChains`, not `network.js`'s `handleOnlinePrivatePayment` — could not be fully verified due to remaining ambiguity in cross-file call ordering; a live reproduction is recommended to confirm the exact race timing.)*

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

**File:** divisible_asset.js (L32-38)
```javascript
			for (var j=0; j<payload.outputs.length; j++){
				var output = payload.outputs[j];
				conn.addQuery(arrQueries, 
					"INSERT INTO outputs (unit, message_index, output_index, address, amount, blinding, asset) VALUES (?,?,?,?,?,?,?)",
					[unit, message_index, j, output.address, parseInt(output.amount), output.blinding, payload.asset]
				);
			}
```
