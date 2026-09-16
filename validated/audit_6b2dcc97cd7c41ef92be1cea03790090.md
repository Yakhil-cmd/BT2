## Title
Reachable assertion (`throw Error`) in private payment chain validation crashes the node — ([File: validation.js])

## Summary
`validatePaymentInputsAndOutputs()` in `validation.js` contains several `throw Error(...)` invariant checks that are meant to be unreachable internal assertions, guarded only by earlier steps that the code *assumes* already sanitized their inputs. For private, fixed-denomination (indivisible) assets, one of these invariants — `isPositiveInteger(src_coin.amount)` — can be violated by data that is fully attacker-controlled and never validated before it reaches the assertion, letting a private-payment counterparty crash the receiving node with a single crafted private-payment chain, analogous to the reachable-assertion DoS described in CVE-2017-13749.

## Finding Description
When a wallet (or hub) receives a private payment chain, it is parsed element-by-element in `parsePrivatePaymentChain()` in `indivisible_asset.js`: [1](#0-0) 

For each element `i`, `validatePrivatePayment()` is called with `prevElement = arrPrivateElements[i+1]` — i.e., the chain element that will only be validated in a *later* iteration: [2](#0-1) 

Inside `validatePrivatePayment()`, for the "transfer" case, the code reads the amount straight out of the *unvalidated* previous element's payload and stores it into `objValidationState.src_coin` without any sanity check: [3](#0-2) 

Only `objPrevPrivateElement.output.blinding` is checked to exist; neither `objPrevPrivateElement.output.address` nor `prev_hidden_output.amount` (`payload.outputs[input.output_index].amount`) is validated at this point — both come directly from attacker-supplied JSON.

This `objValidationState.src_coin` is later consumed in `validation.js`'s `validatePaymentInputsAndOutputs()`, in the branch used specifically for private fixed-denomination assets, where the values are assumed to already be well-formed and are checked with hard `throw Error(...)` instead of a graceful callback error: [4](#0-3) 

Because `prev_hidden_output.amount` was never checked for type/positivity before being copied into `src_coin.amount`, an attacker can set it to `0`, a negative number, a string, `null`, or omit it, causing `isPositiveInteger(src_coin.amount)` to fail and the assertion `throw Error("no src coin amount")` to fire.

This throw happens deep inside nested `async`/callback code (`conn.query` → `async.eachSeries` → `async.forEachOfSeries` → `mutex.lock`), so it is **not** caught by any `try/catch` in the call chain. It propagates as a Node.js "uncaught exception," which is deliberately turned into a hard crash by the global handler: [5](#0-4) 

The comment `// crash the process to avoid ending up in an inconsistent state` confirms this is treated as a fatal, unrecoverable condition — exactly the "reachable assertion abort" pattern from the CVE, except here it is reachable by an ordinary, unprivileged private-payment counterparty rather than by feeding a crafted image to a codec.

## Impact Explanation
Any private-payment counterparty (a role explicitly allowed by scope, e.g. a peer sending a private payment/chain to a wallet, or to a hub relaying private payments) can send one crafted private payment chain to crash the receiving process entirely. If the receiving node is a hub that mediates private payments and message relaying for many light wallets, or a full node/witness process that also participates in private payment relaying, this single message denies service to that whole process until manually restarted, disrupting confirmation and delivery of unrelated units and payments handled by that process. This is a full unhandled-exception process crash, not merely elevated resource usage.

## Likelihood Explanation
No signature bypass, no privileged role, and no race condition is required. The attacker fully controls the entire JSON structure of the private-payment chain elements they send (`arrPrivateElements`), including the values of a previous, not-yet-validated element's hidden output. This is straightforward to trigger deterministically with a single malformed field.

## Recommendation
- In `indivisible_asset.js` `validatePrivatePayment()`, validate `prev_hidden_output.amount` (must be `isPositiveInteger`) and `objPrevPrivateElement.output.address` (must be `isValidAddress`) before populating `objValidationState.src_coin`, returning `callbacks.ifError(...)` on failure instead of deferring to the later assertion.
- In `validation.js`, replace the internal `throw Error("no src_coin")/"no src_output"/"no denomination in src coin"/"no src coin amount"` assertions in the private fixed-denomination transfer branch with graceful `cb(...)` validation errors, since their preconditions are populated from data ultimately originating on the network/from a peer, not purely from trusted internal state.
- More generally, audit other `throw Error(...)` invariants inside `validatePaymentInputsAndOutputs`/`validateAuthor`/`validateParents` that are reachable from attacker-supplied unit/message content and convert them to recoverable validation errors, or wrap unit/joint validation entry points in a try/catch that converts unexpected exceptions into `ifUnitError`/`ifJointError` callbacks instead of allowing them to propagate to `process.on('uncaughtException')`.

## Proof of Concept
1. As a private-payment counterparty, construct an `arrPrivateElements` chain of at least two indivisible-asset private elements, where `arrPrivateElements[1]` (the "previous" element relative to `arrPrivateElements[0]`) has:
   - a valid `output.blinding`
   - `payload.outputs[<output_index>].amount` set to an invalid value (e.g. `0`, `-1`, or a non-numeric string), matching the referenced `output_index` used by `arrPrivateElements[0].payload.inputs[0]`.
2. Send this chain to a wallet/hub via the normal private payment delivery path (`wallet.js` `handlePrivatePaymentChains` → `network.handleOnlinePrivatePayment` → `private_payment.js` `validateAndSavePrivatePaymentChain` → `indivisible_asset.js` `parsePrivatePaymentChain`/`validatePrivatePayment`).
3. During validation of `arrPrivateElements[0]`, `objValidationState.src_coin.amount` is set to the tampered value from the still-unvalidated `arrPrivateElements[1]`.
4. `validation.js` `validatePaymentInputsAndOutputs()` reaches the private fixed-denomination transfer branch and executes `throw Error("no src coin amount")`.
5. The exception is uncaught, is caught only by `process.on('uncaughtException')` in `network.js`, which logs it and re-throws, crashing the Node.js process.

### Citations

**File:** indivisible_asset.js (L106-139)
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
				objValidationState.src_coin = {
					src_output: src_output,
					denomination: payload.denomination,
					amount: prev_hidden_output.amount
				};
```

**File:** indivisible_asset.js (L198-218)
```javascript
	async.forEachOfSeries(
		arrPrivateElements,
		function(objPrivateElement, i, cb){
			if (!objPrivateElement.payload || !objPrivateElement.payload.inputs || !objPrivateElement.payload.inputs[0])
				return cb("invalid payload");
			if (!objPrivateElement.output)
				return cb("no output in private element");
			if (objPrivateElement.payload.asset !== asset)
				return cb("private element has a different asset");
			if (objPrivateElement.payload.denomination !== denomination)
				return cb("private element has a different denomination");
			var prevElement = null; 
			if (i+1 < arrPrivateElements.length){ // excluding issue transaction
				var prevElement = arrPrivateElements[i+1];
				if (prevElement.unit !== objPrivateElement.payload.inputs[0].unit)
					return cb("not referencing previous element unit");
				if (prevElement.message_index !== objPrivateElement.payload.inputs[0].message_index)
					return cb("not referencing previous element message index");
				if (prevElement.output_index !== objPrivateElement.payload.inputs[0].output_index)
					return cb("not referencing previous element output index");
			}
```

**File:** validation.js (L2412-2424)
```javascript
					// for private fixed denominations assets, we can't look up src output in the database 
					// because we validate the entire chain before saving anything.
					// Instead we prepopulate objValidationState with denomination and src_output 
					if (objAsset && objAsset.is_private && objAsset.fixed_denominations){
						if (!objValidationState.src_coin)
							throw Error("no src_coin");
						var src_coin = objValidationState.src_coin;
						if (!src_coin.src_output)
							throw Error("no src_output");
						if (!isPositiveInteger(src_coin.denomination))
							throw Error("no denomination in src coin");
						if (!isPositiveInteger(src_coin.amount))
							throw Error("no src coin amount");
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
