### Title
Private-payment "duplicate" fast-path bypasses full chain-of-custody verification in `validateAndSavePrivatePaymentChain` - ([File: private_payment.js])

### Summary
`private_payment.js` short-circuits validation of an entire private-payment chain (`arrPrivateElements`) whenever the *head* element's revealed output matches an already-stored `outputs` row. This mirrors the Fides "duplicate detection bypasses identity verification" bug class: a duplicate classification on one field (the head output) causes the whole submitted object (the full private chain, including all attacker-suppliable earlier elements) to be treated as `ifOk()`-validated without ever invoking `indivisibleAsset`/`divisibleAsset`'s real chain verification (`validatePrivatePayment`, spend-proof checks, hash-chain linking).

### Finding Description
`validateAndSavePrivatePaymentChain` in `private_payment.js` (lines 61-107) performs a "duplicate" check by querying the `outputs` table for a row matching `unit`, `asset`, `message_index` (and `output_index` for indivisible assets) of the **head** element only: [1](#0-0) 

If a matching stored row exists with a non-null `address`, it compares only the head element's *claimed/revealed output fields* (`amount`, `address`, `blinding`, `denomination`) against the stored row and, on a match, immediately calls `transaction_callbacks.ifOk()` — skipping the call to `assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks)` entirely: [2](#0-1) 

That skipped call is what actually performs cryptographic chain verification: recomputing output hashes, validating spend proofs against `input.unit`/`input.message_index`/`input.output_index`, and linking each element to the previous one (`objPrevPrivateElement`) via `spend_proof = objectHash.getBase64Hash({...})` and `graph.determineIfIncluded`: [3](#0-2) [4](#0-3) 

Because the duplicate test only examines the **head** element's revealed fields — which are public/observable once a legitimate sender has revealed them to any recipient (the whole point of a private chain reveal) — an attacker who knows the head unit, message_index, output_index, and the revealed `address`/`amount`/`blinding`/`denomination` of an output that already exists in the recipient's `outputs` table can submit a completely different, unverified `arrPrivateElements[1..n]` "back-chain" (fabricated spend proofs, forged intermediate units, or an unrelated/invalid issuance history) attached to that same head element. The duplicate branch matches on the head alone and returns success without ever validating the newly submitted back-chain.

This is entered via `wallet.js`'s `handlePrivatePaymentChains` → `network.handleOnlinePrivatePayment` → `private_payment.js` `validateAndSavePrivatePaymentChain`, reachable by any device peer sending a private-payment chain message, i.e. an unprivileged paired device / private-payment counterparty: [5](#0-4) 

On success, the wallet marks the chain as validated (`assocValidatedByKey[key] = true`), fires `all_private_payments_handled`/`emitNewPrivatePaymentReceived` with the **entire attacker-supplied `arrChains`**, and — critically — forwards the unverified chain to other members of the output addresses / shared wallets, propagating trust in data that was never cryptographically checked: [6](#0-5) [7](#0-6) 

### Impact Explanation
The duplicate fast-path causes the wallet/hub to treat an entire private-payment provenance chain as fully verified when only the terminal, already-public output was checked. Consequences reachable from a single posted private-chain message:
- Forwarding of an attacker-fabricated back-chain to other correspondents/shared-wallet members as if it were validated (`forwardPrivateChainsToOtherMembersOfOutputAddresses`), corrupting the recipients' view of that private asset's provenance.
- UI/event consumers (`emitNewPrivatePaymentReceived`, `all_private_payments_handled`) receive and may act on the unverified chain contents, since the API contract of `ifOk()`/`ifAccepted` implies full cryptographic validation occurred.
- This is a verification-bypass on the AA/private-payment trust boundary equivalent to the Fides "approved without verification" pattern: a classifier (duplicate detection) short-circuits the security-critical validator, and downstream logic acts on the unverified object as though it were verified.

Because the actual `outputs` row already exists and nothing new is persisted, this does not directly create a double-spend of a stable output or new supply, so it stops short of "unauthorized spending" — but it does cause the node/wallet to accept and propagate falsified custody data as validated, i.e., a form of node disagreement about what is actually verified vs. unverified private-payment history.

### Likelihood Explanation
Exploitation requires an attacker to already know the exact revealed values of a specific private output (address, amount, blinding, denomination) tied to a specific unit/message_index/output_index — information that is inherently exposed to counterparties once the legitimate owner reveals it (a normal part of private-payment chain forwarding). Any paired device or private-payment counterparty that already received one legitimate chain can then re-send a doctored chain sharing the same head element to trigger the bypass. No cryptographic break is required; only crafting a message with a matching head and an arbitrary back-chain.

### Recommendation
The duplicate short-circuit should not return `ifOk()` based solely on the head element matching a previously stored output. Either drop the optimization entirely (always run full chain validation through `assetModule.validateAndSavePrivatePaymentChain`), or extend the duplicate check to also verify that the entire submitted back-chain (`arrPrivateElements[1..n]`) hashes to the same known/previously-validated chain (e.g., compare a hash of the full chain, not just the head fields) before skipping re-validation.

### Proof of Concept
1. Attacker device is a legitimate counterparty of a private asset output `O` at `unit=U`, `message_index=M`, `output_index=I`, and has observed the revealed `{address, amount, blinding, denomination}` for `O` (public once shared, per `private_payment.js:76-89`).
2. Attacker crafts a new `arrPrivateElements` chain whose head element (`arrPrivateElements[0]`) has the same `unit`, `asset`, `message_index`, `output_index`, and reveals the identical `{address, amount, blinding, denomination}` as stored, but whose earlier chain elements (`arrPrivateElements[1..n]`) reference forged/mismatched spend proofs, an unrelated issuance path, or an invalid signature chain.
3. Attacker sends this chain via the wallet device-message channel (`handlePrivatePaymentChains` in `wallet.js`), which calls `network.handleOnlinePrivatePayment` → `private_payment.js`'s `validateAndSavePrivatePaymentChain`.
4. The duplicate-check SQL at `private_payment.js:62-69` matches the stored row; the field comparison at `private_payment.js:83-98` matches on the head element; `bDuplicate` is `true`.
5. `transaction_callbacks.ifOk()` is invoked (`private_payment.js:101`) without ever calling `indivisibleAsset`/`divisibleAsset`'s `validateAndSavePrivatePaymentChain`, so the forged back-chain (`arrPrivateElements[1..n]`) is never checked against `validatePrivatePayment`'s spend-proof/hash-link logic (`indivisible_asset.js:20-120`).
6. The caller in `wallet.js` marks the chain validated and forwards the full attacker-controlled `arrChains` (including the forged back-chain) to other members of the output addresses (`wallet.js:1071-1114`), propagating unverified provenance data as if it had passed cryptographic validation.

### Citations

**File:** private_payment.js (L61-69)
```javascript
					// check if duplicate
					var sql = "SELECT address, denomination, amount, blinding FROM outputs WHERE unit=? AND asset=? AND message_index=?";
					var params = [headElement.unit, asset, headElement.message_index];
					if (objAsset.fixed_denominations){
						if (!ValidationUtils.isNonnegativeInteger(headElement.output_index))
							return transaction_callbacks.ifError("no output index in head private element");
						sql += " AND output_index=?";
						params.push(headElement.output_index);
					}
```

**File:** private_payment.js (L76-105)
```javascript
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
```

**File:** indivisible_asset.js (L20-52)
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

**File:** indivisible_asset.js (L106-120)
```javascript
				var src_output = objPrevPrivateElement.output;
				var prev_hidden_output = objPrevPrivateElement.payload.outputs[input.output_index];
				if (!prev_hidden_output)
					return callbacks.ifError("no prev hidden output");
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
```

**File:** wallet.js (L1035-1063)
```javascript
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

**File:** wallet.js (L1071-1076)
```javascript
			checkIfAllValidated();
			handledChainsCache[cache_key] = Date.now();
			callbacks.ifOk();
			// forward the chains to other members of output addresses
			if (!body.forwarded)
				forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, true);
```

**File:** wallet.js (L1082-1114)
```javascript
function forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, bForwarded, conn, onSaved){
	console.log("forwardPrivateChainsToOtherMembersOfOutputAddresses", arrChains);
	var assocOutputAddresses = {};
	arrChains.forEach(function(arrPrivateElements){
		var objHeadPrivateElement = arrPrivateElements[0];
		var payload = objHeadPrivateElement.payload;
		payload.outputs.forEach(function(output){
			if (output.address)
				assocOutputAddresses[output.address] = true;
		});
		if (objHeadPrivateElement.output && objHeadPrivateElement.output.address)
			assocOutputAddresses[objHeadPrivateElement.output.address] = true;
	});
	var arrOutputAddresses = Object.keys(assocOutputAddresses);
	console.log("output addresses", arrOutputAddresses);
	conn = conn || db;
	if (!onSaved)
		onSaved = function(){};
	readWalletsByAddresses(conn, arrOutputAddresses, function(arrWallets){
		if (arrWallets.length === 0){
		//	breadcrumbs.add("forwardPrivateChainsToOtherMembersOfOutputAddresses: " + JSON.stringify(arrChains)); // remove in livenet
		//	eventBus.emit('nonfatal_error', "not my wallet? output addresses: "+arrOutputAddresses.join(', '), new Error());
		//	throw Error("not my wallet? output addresses: "+arrOutputAddresses.join(', '));
		}
		var arrFuncs = [];
		if (arrWallets.length > 0)
			arrFuncs.push(function(cb){
				walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets(arrChains, arrWallets, bForwarded, conn, cb);
			});
		arrFuncs.push(function(cb){
			walletDefinedByAddresses.forwardPrivateChainsToOtherMembersOfAddresses(arrChains, arrOutputAddresses, bForwarded, conn, cb);
		});
		async.series(arrFuncs, onSaved);
```
