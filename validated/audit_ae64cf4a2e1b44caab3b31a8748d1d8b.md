### Title
Early loop abort in `handlePrivatePaymentChains` causes valid private-payment chains in the same batch to be silently dropped - ([File: wallet.js])

### Summary
`handlePrivatePaymentChains` in `wallet.js` iterates over a batch of private-payment chains (`body.chains`) sent in a single `private_payments` message using `async.eachSeries`. As soon as one chain in the array fails validation (`ifError`/`ifValidationError`), the iteration calls `cb("an error")`, which stops `async.eachSeries` immediately and invokes the outer `ifError` callback for the whole batch, without ever attempting the remaining, subsequent chains in the array.

### Finding Description
`async.eachSeries` is used specifically because it processes items sequentially and stops at the first error [1](#0-0) . Inside the iterator, if `network.handleOnlinePrivatePayment` returns `ifError` or `ifValidationError` for one chain, the code calls `cb("an error")` [2](#0-1) , which is the standard `async` idiom to abort the whole series early. The final callback of `async.eachSeries` treats any such error by calling `cancelAllKeys()` and `callbacks.ifError(err)` for the entire batch [3](#0-2) , discarding whatever had not yet been processed.

This is structurally the same bug class as the ZetaChain finding: a single malformed/invalid item placed in a batch causes the batch-processing loop to exit early, while chains/items that came later in the same array are never even attempted — they are effectively "skipped" rather than being individually rejected and having the rest of the batch continue. Any party able to compose or forward a `private_payments` message containing multiple chains (e.g., a private-payment counterparty relaying several chains at once via `forwardPrivateChainsToOtherMembersOfOutputAddresses`/`...SharedAddresses`) can place one intentionally-broken chain ahead of legitimate ones to prevent the legitimate chains from being validated and saved in that batch.

### Impact Explanation
If a batch of private payment chains addressed to a wallet is delivered together and an attacker (or a buggy/malicious relaying peer) manages to include one invalid chain earlier in the array, the legitimate chains that follow it are never validated, never saved to the receiver's spend-proof/output tables, and the `ifOk`/forwarding logic (`forwardPrivateChainsToOtherMembersOfOutputAddresses`) for those chains never runs. This can cause the receiving wallet to silently fail to receive/record private payments it should have received, and can prevent private outputs from being forwarded to co-signers, leading to inconsistent or missing private-payment state (funds effectively "lost" from the receiver's perspective until the payment is somehow resent/rebroadcast through a different channel).

### Likelihood Explanation
Exploitation requires an attacker to control or influence the composition of the `chains` array sent via `private_payments`. Whether an attacker can force other, unrelated users' legitimate chains into the same batch as their own malicious chain is not verifiable from static analysis alone — this depends on hub/device relaying and batching behavior (`forwardPrivateChainsToOtherMembersOfSharedAddresses`) that was not fully traced. If a single sender can only submit their own chains, the impact is limited to self-inflicted DoS on their own multi-output/multi-chain sends. I was unable to confirm within available tool calls whether hub or forwarding logic ever merges chains from different unrelated principals into a single `private_payments` batch, which materially affects how "reachable" this is as a cross-user impact versus a self-limited annoyance.

### Recommendation
Do not use `async.eachSeries` with early-abort semantics for independent chain validation. Continue processing every chain in the batch regardless of individual failures — collect a per-chain result map, call `ifError` (or record failure) only for the offending chain, and still complete validation/saving of the remaining chains, then report the aggregate result to the caller.

### Proof of Concept
Not independently reproduced (no runtime/execution tool available in this session). The finding is derived from static code inspection of the control flow in `handlePrivatePaymentChains` [4](#0-3) , showing that `async.eachSeries` aborts on the first `cb(err)`, which occurs whenever any single chain in `body.chains` fails validation. A concrete PoC would require: (1) crafting a `private_payments` message with `chains = [invalid_chain, legit_chain_1, legit_chain_2]`, (2) sending it to a target device/wallet, and (3) observing that `legit_chain_1`/`legit_chain_2` are never validated or saved because the loop stops at `invalid_chain`. This step was not executed due to lack of a live environment in this session, so the practical batching/forwarding conditions needed to combine an attacker's chain with a victim's legitimate chain remain unverified.

### Citations

**File:** wallet.js (L1020-1071)
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
		},
		function(err){
			bParsingComplete = true;
			if (err){
				cancelAllKeys();
				return callbacks.ifError(err);
			}
			checkIfAllValidated();
```
