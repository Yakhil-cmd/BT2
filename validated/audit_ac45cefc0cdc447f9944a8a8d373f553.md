### Title
`emitNewPrivatePaymentReceived` fires the `received_payment` credit-notification event even for private-payment chains that were already accepted earlier (duplicate re-delivery), allowing a private-payment counterparty to trigger duplicate off-chain crediting - ([File: wallet.js])

### Summary
The Trail-of-Bits report is about an on-chain event (`PendingDepositRefund`) that omits a unique identifier (the deposit nonce), so an off-chain watcher can misattribute *which* deposit was refunded and credit the same funds twice. In ocore, the analogous mechanism is `handlePrivatePaymentChains()` / `emitNewPrivatePaymentReceived()` in `wallet.js`: whenever a device peer (the private-payment counterparty) sends a `private_payments` message that validates successfully, the wallet unconditionally emits the `received_payment` event that headless-wallet/exchange bots use to credit a user's balance - even when the underlying private-payment chain has *already been accepted and credited before* and is only being treated as "OK" a second time because of the duplicate-suppression logic in `private_payment.js`. There is no unique, persisted marker (equivalent to a "nonce") passed to the credited-amount event that lets the listener distinguish "genuinely new payment" from "resend of an already-credited payment," so a malicious counterparty can resend the same private chain (with a different message wrapping to defeat the message-level dedup cache) and cause the receiving wallet to notify its off-chain credit logic again.

### Finding Description
`private_payment.js#validateAndSavePrivatePaymentChain` detects if a `(unit, message_index[, output_index])` output has already been saved with an address, and if the new payload matches, treats it as a **duplicate** and calls `transaction_callbacks.ifOk()` without re-inserting anything: [1](#0-0) 

This "duplicate → still call ifOk()" behavior is by design at the storage layer (so a legitimate resend during a bad network / recomposed message doesn't error out the sender). However, the caller in `wallet.js` that receives the whole batch of chains from a device message does not distinguish between "this call to `ifOk` represents brand‑new funds" and "this call to `ifOk` represents a chain that was already accepted before": [2](#0-1) 

`checkIfAllValidated()` fires `emitNewPrivatePaymentReceived(from_address, arrChains, current_message_counter)` any time every chain in the batch validates as `ifOk`/`ifAccepted` — regardless of whether the underlying save was a fresh insert or a duplicate short‑circuit. `network.handleOnlinePrivatePayment` → `privatePayment.validateAndSavePrivatePaymentChain` → asset module's `validateAndSavePrivatePaymentChain` reports success (`ifOk`) identically in both the "new" and the "duplicate" case: [3](#0-2) 

`emitNewPrivatePaymentReceived` itself only reads amounts out of the payload/outputs that belong to "my" addresses, and emits a single `received_payment` event with the summed amount, the payer's device address, the asset, and an internal `message_counter` — none of which is a stable, unique identifier of the underlying deposit/output (the private-chain equivalent of the missing "nonce" in the Solidity report): [4](#0-3) 

The only de-duplication guard that exists at this layer is the very short-lived, in-memory `handledChainsCache` keyed by `objectHash.getBase64Hash(arrChains)` (the *exact byte-for-byte serialization* of the message), which only suppresses a byte-identical resend and is cleared after roughly an hour, and does not survive a process restart: [5](#0-4) 

Because the hash is computed over the whole `arrChains` array (not the semantic identity of the underlying deposit output), a malicious private-payment counterparty can trivially defeat this cache by resending the same chains split/batched differently, waiting for the cache TTL to expire, or restarting the connection after the hub/wallet process restarts, causing `checkIfAllValidated`/`emitNewPrivatePaymentReceived` to fire the `received_payment` event again for an already-spent/already-credited output that is now silently absorbed as a "duplicate" by the storage layer.

### Impact Explanation
Third-party off-chain integrations (e.g. exchange headless wallets, deposit bots) that listen to the `received_payment` event to credit user balances for privately transferred assets have no reliable way, from the event payload alone, to know that a given notification corresponds to a payment they already credited. This is architecturally the exact class of bug described in the report: the event that off-chain logic keys off of does not carry a unique identifier of the deposit/output being referenced, so a counterparty can resend the payment notification path and get double credit for a single one-time private transfer — a direct fund-loss/double-spend-equivalent issue for any bot or service built against this event, exactly as Eve exploited the missing nonce in `PendingDepositRefund`.

### Likelihood Explanation
The trigger requires only that the attacker control a paired device (the payer) and be able to resend a `private_payments` device message to the victim's wallet — no special privileges, mining power, or protocol violation are needed. The in-memory cache is trivially bypassed by changing serialization order/batching or waiting out its TTL, and it is not persisted, so a hub/wallet restart (a normal operational event) also resets it. The underlying storage-layer "duplicate → ifOk" design (needed for legitimate resend tolerance) is exactly what makes the notification path unable to distinguish new vs. repeat credit events, so likelihood is moderate-to-high wherever off-chain credit logic is built directly on the `received_payment` event without independently deduplicating by unit/output.

### Recommendation
**Short term:** Change `validateAndSavePrivatePaymentChain` (`private_payment.js`) to explicitly report back to the caller whether the outcome was a fresh save or a detected duplicate (e.g., `ifOk(bWasDuplicate)`), and have `wallet.js`'s `checkIfAllValidated`/`emitNewPrivatePaymentReceived` suppress the `received_payment` notification (or clearly flag it as a duplicate) when any underlying chain was a duplicate. Additionally, emit the specific unit/message_index/output_index (or a stable output-hash identifier) together with the `received_payment` event so that any consuming code can perform its own idempotency check instead of relying on amount + device address alone.

**Long term:** Document the exact uniqueness/idempotency guarantees (or lack thereof) of every wallet-level event intended to drive off-chain accounting (`received_payment`, `new_my_transactions`, `aa_response`, etc.), and provide a canonical "processed deposit" identifier in each such event so third-party integrations cannot be tricked into crediting the same private transfer twice.

### Proof of Concept
1. Attacker (device A, a private-payment counterparty) sends a legitimate `private_payments` message with chain `C` (one output to victim's address) to victim's wallet (device B), which runs a bot listening on `received_payment` to credit an external ledger. Wallet B validates `C`, saves it, and the bot credits the user.
2. Attacker resends the identical semantic payment as a new device message: either (a) after the ~1 hour `handledChainsCache` TTL has elapsed, (b) after the wallet process restarts (clearing the in-memory cache), or (c) by re-serializing/re-batching the same `arrChains` payload so `objectHash.getBase64Hash(arrChains)` differs from the first send.
3. `handlePrivatePaymentChains` in `wallet.js` does not find a cache hit, so it proceeds to `network.handleOnlinePrivatePayment` → `privatePayment.validateAndSavePrivatePaymentChain`, which detects the output row already has an address filled matching amount/blinding, calls `transaction_callbacks.ifOk()` (the "duplicate" branch), and no new row is written.
4. Back in `wallet.js`, `ifAccepted`/`ifOk` still marks the chain validated, `checkIfAllValidated()` runs, and `emitNewPrivatePaymentReceived` fires `received_payment` a second time with the same amount/asset/payer address.
5. The bot, unable to distinguish this from a genuinely new transfer (there is no unique identifier in the event), credits the user's external balance again for funds that were only sent once — resulting in the bot paying out more than it received, the same fund-duplication pattern as the reported Solidity bug.

### Citations

**File:** private_payment.js (L73-102)
```javascript
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
```

**File:** wallet.js (L948-984)
```javascript
var handledChainsCache = {};
setInterval(() => {
	for (let cache_key in handledChainsCache)
		if (handledChainsCache[cache_key] < Date.now() - 3600 * 1000)
			delete handledChainsCache[cache_key];
}, 3600 * 1000); // clear cache every hour

function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
	if (!arrChains.every(c =>
		isNonemptyArray(c) &&
		c.every(e =>
			isNonemptyObject(e) &&
			isNonemptyString(e.unit) &&
			isNonemptyObject(e.payload) &&
			isNonemptyString(e.payload.asset) &&
			isNonemptyArray(e.payload.inputs) &&
			isNonemptyArray(e.payload.outputs) &&
			e.payload.inputs.every(isNonemptyObject) &&
			e.payload.outputs.every(isNonemptyObject)
		)
	))
		return callbacks.ifError("malformed private chain");
	try {
		var cache_key = objectHash.getBase64Hash(arrChains);
	}
	catch (e) {
		return callbacks.ifError("chains hash failed: " + e.toString());		
	}
	if (handledChainsCache[cache_key]) {
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		return callbacks.ifOk();
	}
	profiler.increment();
```

**File:** wallet.js (L998-1018)
```javascript
	var checkIfAllValidated = function(){
		if (!assocValidatedByKey) // duplicate call - ignore
			return console.log('duplicate call of checkIfAllValidated');
		for (var key in assocValidatedByKey)
			if (!assocValidatedByKey[key])
				return console.log('not all private payments validated yet');
		eventBus.emit('all_private_payments_handled', from_address);
		eventBus.emit('all_private_payments_handled-' + arrChains[0][0].unit);
		assocValidatedByKey = null; // to avoid duplicate calls
		if (!body.forwarded){
			if (from_address) emitNewPrivatePaymentReceived(from_address, arrChains, current_message_counter);
			// note, this forwarding won't work if the user closes the wallet before validation of the private chains
			var arrUnits = arrChains.map(function(arrPrivateElements){ return arrPrivateElements[0].unit; });
			db.query("SELECT address FROM unit_authors WHERE unit IN(?)", [arrUnits], function(rows){
				var arrAuthorAddresses = rows.map(function(row){ return row.address; });
				// if the addresses are not shared, it doesn't forward anything
				forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChains, arrAuthorAddresses, from_address, true);
			});
		}
		profiler.print();
	};
```

**File:** wallet.js (L1138-1201)
```javascript
function emitNewPrivatePaymentReceived(payer_device_address, arrChains, message_counter){
	console.log('emitNewPrivatePaymentReceived');
	walletGeneral.readMyAddresses(function(arrAddresses){
		var assocAmountsByAsset = {};
		var assocMyReceivingAddresses = {};
		var units = [];
		arrChains.forEach(function(arrPrivateElements){
			var objHeadPrivateElement = arrPrivateElements[0];
			units.push(objHeadPrivateElement.unit);
			var payload = objHeadPrivateElement.payload;
			var asset = payload.asset || 'base';
			if (!assocAmountsByAsset[asset])
				assocAmountsByAsset[asset] = 0;
			if (!objHeadPrivateElement.output) { // divisible asset
				let arrMyOutputAmounts = [];
				payload.outputs.forEach(function (output) {
					if (output.address && arrAddresses.indexOf(output.address) >= 0) {
						arrMyOutputAmounts.push(output.amount);
						assocMyReceivingAddresses[output.address] = true;
					}
				});
				if (arrMyOutputAmounts.length > 1)
					console.log('Multiple outputs to my addresses in a divisible asset, ignoring', asset, payload.outputs);
				else if (arrMyOutputAmounts.length === 1)
					assocAmountsByAsset[asset] += arrMyOutputAmounts[0];
			}
			// indivisible
			var output = objHeadPrivateElement.output;
			if (output && output.address && arrAddresses.indexOf(output.address) >= 0){
				assocAmountsByAsset[asset] += payload.outputs[objHeadPrivateElement.output_index].amount;
				assocMyReceivingAddresses[output.address] = true;
			}
		});
		console.log('assocAmountsByAsset', assocAmountsByAsset);
		var arrMyReceivingAddresses = Object.keys(assocMyReceivingAddresses);
		if (arrMyReceivingAddresses.length === 0)
			return;
		// skip notification if the payment was from our adddress
		db.query("SELECT 1 FROM unit_authors JOIN my_addresses USING(address) WHERE unit IN(?)\n\
			UNION SELECT 1 FROM unit_authors JOIN shared_addresses ON unit_authors.address=shared_addresses.shared_address WHERE unit IN(?)", [units, units],
			function(rows) {
				if (rows.length)
					return;
				db.query("SELECT 1 FROM shared_addresses WHERE shared_address IN(?)", [arrMyReceivingAddresses], function(rows){
					var emit = function(address_type) {
						for (var asset in assocAmountsByAsset)
							if (assocAmountsByAsset[asset])
								eventBus.emit('received_payment', payer_device_address, assocAmountsByAsset[asset], asset, message_counter, address_type);
					}
					var bToSharedAddress = (rows.length > 0);
					if (!bToSharedAddress) {
						db.query("SELECT 1 FROM my_watched_addresses WHERE address IN(?)", [arrMyReceivingAddresses], function(rows){
							if (rows.length > 0)
								emit('watched');
							else
								emit('main');
						});
					} else
						emit('shared');
				});
			}
		);
	});
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
