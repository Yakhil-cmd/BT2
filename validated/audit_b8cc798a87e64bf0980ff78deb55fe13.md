## Title
Autonomous Agent (AA) payment messages sending fixed-denomination (indivisible) assets are silently dropped instead of bouncing the trigger, causing state updates to proceed as if the transfer succeeded - ([File: aa_composer.js])

### Summary
This is the ocore analog of the "transfers of collateral tokens can silently fail" class of bug. In the external report, `FraxPool` did not check the return value of `transfer`/`transferFrom`, so state (minted FRAX) advanced as though a collateral transfer succeeded even when it silently failed. In ocore's Autonomous Agent (AA) engine, when an AA's `messages` template includes a `payment` message that pays out a `fixed_denominations` (indivisible) asset, the engine does not bounce the trigger or report an error - it silently strips that message from the response unit while letting the rest of the AA's execution (including its `state` update formula) proceed normally, exactly as if the payment had gone through.

### Finding Description
When `handleTrigger` builds the AA's response unit in `sendUnit`, it iterates over the AA's `messages` and, for each `payment` message referencing a non-base asset, loads the asset properties and checks `fixed_denominations`: [1](#0-0) 

If the asset is `fixed_denominations`, the code calls `cb()` with no error - explicitly commented `// will skip it later` - instead of failing/bouncing the trigger. Later, all `payment` messages for `fixed_denominations` assets are filtered out of the final message list entirely: [2](#0-1) 

Crucially, this filtering only removes `payment` messages; any accompanying `state` message (which contains the AA's `state` update formula, e.g. decrementing an inventory counter, marking an item "sold", or crediting `response`) is left untouched and is executed unconditionally via `executeStateUpdateFormula` further down the same function: [3](#0-2) 

There is no static restriction in `aa_validation.js` that prevents an AA definition from specifying a payment of a `fixed_denominations` asset (that property can only be known at runtime by querying the asset), so any AA author can (even unintentionally) write oscript that attempts to pay out an indivisible asset as part of a response to a trigger.

The result: the trigger sender's payment (e.g. bytes sent to "buy" an indivisible token/ticket) is retained by the AA, the AA's internal state is updated as though the countervailing payment was sent, but the actual token transfer never occurs and no bounce/refund happens. This is functionally identical to the reported FraxPool bug class: an on-chain "transfer" that fails without reverting, letting dependent accounting advance as if it succeeded.

### Impact Explanation
Any user (unprivileged trigger sender) who sends a trigger unit to an AA whose oscript is designed to pay out a `fixed_denominations` asset as compensation loses the funds they sent to the AA and never receives the promised asset, while the AA's own bookkeeping (e.g. `var['stock']`, `var['sold']`, `response['ticket']`) is silently corrupted to reflect a successful payment. Because state changes are irreversible and committed via `updateFinalAABalances`/`fixStateVars`, this could be repeated to systematically drain trigger senders' funds or desynchronize an AA's internal accounting from its real token custody, a concrete AA fund-loss/inconsistency scenario.

### Likelihood Explanation
Reachable directly by any address sending a properly formed trigger unit to an AA that defines such a payment message - no privileged access, hub, or peer manipulation required. The only precondition is that the AA's oscript, evaluated at trigger time, produces a `payment` message referencing an asset that happens to be `fixed_denominations`. Since AA authors cannot statically know or enforce this at definition time (asset properties are resolved by a database lookup during execution), this can be triggered either by a poorly written AA or deliberately targeted by an attacker who controls or influences which asset is referenced (e.g., via `trigger.data.asset`).

### Recommendation
Treat an attempted payment of a `fixed_denominations` (or `is_private`) asset from an AA as a hard error that bounces the entire trigger (as is already done for `is_private` assets at line 1329-1330), rather than silently dropping just the payment message while letting the rest of the response (including `state` updates) proceed. This ensures the AA's internal state can never diverge from what was actually transferred on-chain.

### Proof of Concept
1. Deploy an AA whose `messages.cases` include, on a trigger condition:
   - a `payment` message sending an indivisible asset (`fixed_denominations: true`) to `trigger.address`
   - a `state` message that does `var['sold'] += 1;` or similar bookkeeping assuming the payment succeeded
2. Send a trigger unit satisfying the condition, paying the AA in bytes.
3. Observe that `aa_composer.js`'s `sendUnit` drops the indivisible-asset payment message (per `aa_composer.js:1327-1328` and `1356`) but still executes and commits the `state` message via `executeStateUpdateFormula` (`aa_composer.js:1405-1411`), so `var['sold']` is incremented and the trigger sender's payment is consumed, yet no output ever pays the indivisible asset to the trigger sender.

### Citations

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_composer.js (L1346-1361)
```javascript
			function (err) {
				if (err)
					return bounce(err);
				// remove messages with no outputs again (send-all outputs might get removed if nothing found for them)
				messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
				if (messages.length === 0) {
					error_message = 'no messages after removing 0-outputs (2nd pass)';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
				messages = messages.filter(function (message) { return (message.app !== 'payment' || !message.payload.asset || !assetInfos[message.payload.asset].fixed_denominations); });
				if (messages.length === 0) {
					error_message = 'no messages after removing fixed denominations';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```

**File:** aa_composer.js (L1403-1411)
```javascript
						objUnit.unit = objectHash.getUnitHash(objUnit);
						console.log('unit', util.inspect(objUnit, { depth: 6 }))
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```
