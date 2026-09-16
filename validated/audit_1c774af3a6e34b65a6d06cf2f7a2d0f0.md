### Title
Uncaught `throw Error` on malformed private-payment chain elements crashes the node process - ([File: validation.js])

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` contains multiple `throw Error(...)` statements guarding internal invariants of `objValidationState.src_coin` when validating a **private, fixed-denomination asset transfer input**. These invariants are expected to be established beforehand by the private-payment validation path (`private_payment.js` → `indivisible_asset.js`), which is fed directly from data supplied by a private-payment counterparty. If a malicious counterparty sends a malformed/incomplete private payment chain such that `objValidationState.src_coin` (or its `src_output`, `denomination`, `amount`) is missing or malformed by the time this code runs, the `throw Error(...)` propagates as an **uncaught exception** rather than being surfaced through the callback-based error path (`cb(...)`).

### Finding Description
In the `"transfer"` case of `validatePaymentInputsAndOutputs`, when the asset is private with fixed denominations, the code reads the required source-coin data directly from `objValidationState.src_coin` instead of the database (comment: "private fixed denominations assets ... we validate the entire chain before saving anything ... prepopulate objValidationState with denomination and src_output"): [1](#0-0) 

If any of these fields are absent (e.g., due to a malformed or truncated private payment chain sent by the payer), the code does not return a graceful validation error via `cb(...)`; it directly `throw`s. All other error conditions in this same function correctly funnel through `return cb("...")`, making these four lines an inconsistency where an attacker-influenced code path bypasses the normal error-handling flow and instead raises a JavaScript exception synchronously inside a query callback, which Node.js cannot catch with the surrounding `async`/`try` machinery.

Network-level protection deliberately turns any uncaught exception into a full process crash: [2](#0-1) 

The `private-payment counterparty` path is explicitly listed as one of the actors this analog is scoped to reach. The entry point for such attacker-controlled chains is `validateAndSavePrivatePaymentChain` in `private_payment.js`, which parses attacker-supplied `arrPrivateElements` and delegates to `indivisible_asset.js`/`divisible_asset.js`, eventually reaching `validatePaymentInputsAndOutputs`: [3](#0-2) 

I was not able to fully trace how `indivisible_asset.js` populates `objValidationState.src_coin` from the chain elements (its full body wasn't returned by search), so I cannot conclusively prove the exact malformed payload shape needed to leave `src_coin`/`src_output` unset. This is the residual uncertainty in this analog — the reachability of the throw depends on whether `indivisible_asset.js` always guarantees these fields are populated before calling into `validatePaymentInputsAndOutputs`, or whether a crafted chain can bypass that population.

### Impact Explanation
If reachable, this is a process-crashing bug: any node/wallet/hub that validates an inbound private payment chain from an untrusted counterparty would hit an uncaught exception and, per the `uncaughtException` handler in `network.js`, deliberately re-throw to terminate the process. This matches the reachable-impact bar for "network unable to confirm new units" (repeated crash-on-receipt against a hub/wallet acting as validator) if the crash can be triggered reliably and repeatedly by an untrusted private-payment counterparty.

### Likelihood Explanation
Likelihood is uncertain/moderate: the private payment protocol is explicitly designed to accept payloads from a counterparty who is not otherwise trusted, and reaching `validatePaymentInputsAndOutputs`'s private-fixed-denomination transfer branch is a documented, reachable code path. However, without visibility into `indivisible_asset.js`'s exact pre-population logic for `src_coin`, I cannot confirm with certainty that a malformed chain element actually skips population rather than being rejected earlier with a normal validation error.

### Recommendation
Replace the `throw Error(...)` invariant checks in the private fixed-denomination transfer branch of `validatePaymentInputsAndOutputs` (`validation.js` lines ~2416-2424) with graceful `return cb("...")` error returns, consistent with the rest of the function, so that malformed/incomplete private-payment chain data results in a validation error rather than an uncaught exception and process crash. Additionally, audit `indivisible_asset.js`/`divisible_asset.js` to guarantee `objValidationState.src_coin` is always fully populated (or the flow is rejected earlier) before invoking core validation.

### Proof of Concept
Conceptual PoC (not fully verified end-to-end due to missing visibility into `indivisible_asset.js`):
1. A malicious private-payment counterparty constructs a private payment chain (`arrPrivateElements`) for a private, fixed-denomination asset, referencing a "transfer" input whose corresponding `src_coin` data is incomplete or inconsistent (e.g., missing `src_output`, `denomination`, or `amount` fields) in a way that `indivisible_asset.js` fails to populate `objValidationState.src_coin` correctly before calling `validatePaymentInputsAndOutputs`.
2. This chain is sent to the victim (wallet/hub) via `private_payment.js`'s `validateAndSavePrivatePaymentChain`.
3. Validation reaches the `"transfer"` branch for the private fixed-denomination asset in `validation.js`, hits one of the `throw Error("no src_coin")` / `throw Error("no src_output")` / `throw Error("no denomination in src coin")` / `throw Error("no src coin amount")` statements.
4. The exception is uncaught, triggers `process.on('uncaughtException', ...)` in `network.js`, which re-throws and crashes the victim's node process — denial of service, directly analogous to the crafted-input assertion-failure crash described in CVE-2017-8372.

### Citations

**File:** validation.js (L2415-2424)
```javascript
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

**File:** private_payment.js (L23-105)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
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
```
