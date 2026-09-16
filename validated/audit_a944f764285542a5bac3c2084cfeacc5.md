### Title
Unauthorized `throw Error(...)` in private indivisible-asset transfer validation crashes the node process - (File: `validation.js`)

### Summary
`validation.js`'s `validatePaymentInputsAndOutputs()` contains synchronous `throw Error(...)` statements in the private-asset "transfer" input branch that are reachable from data supplied by a private-payment counterparty, rather than being routed through the normal `callback(err)` error path. Because these throws occur deep inside asynchronous validation call chains that are not wrapped in `try/catch` at every level, an uncaught exception propagates to `process.on('uncaughtException')` in `network.js`, which explicitly re-throws to kill the process: [1](#0-0) 

### Finding Description
When validating a `transfer` input for a private, fixed-denomination asset, ocore does not look up the source output in the database (since the whole chain is validated before saving). Instead, it relies on `objValidationState.src_coin`, which is populated from the private payment chain data forwarded by the sending counterparty: [2](#0-1) 

If `src_coin`, `src_coin.src_output`, `src_coin.denomination`, or `src_coin.amount` are missing/malformed, the code does `throw Error(...)` instead of calling `cb(err)` like every other validation failure in this function. This is inconsistent with the rest of `validatePaymentInputsAndOutputs`, where malformed input is reported via the `callback` mechanism (e.g. `return cb("output owner is not among authors")` a few lines below the same block).

This validation path is invoked when a wallet receives a private payment chain from an untrusted private-payment counterparty via `private_payment.validateAndSavePrivatePaymentChain()`, which for fixed-denomination (indivisible) private assets calls `indivisible_asset.js`'s `validateAndSavePrivatePaymentChain`, which ultimately calls `validation.validate()`: [3](#0-2) 

The private-payment sender fully controls the wire format of the joint/payload sent to the recipient before it is ever validated, so a malicious sender can craft a `src_coin`/private-element payload that omits `denomination` or `amount`, or that omits `src_output`, triggering the `throw Error(...)` instead of a graceful validation error.

Similar bare `throw Error(...)` statements exist elsewhere in the same function/module for double-spend bookkeeping (e.g. `validation.js:1673`, `1688`, `1692`, `2458`, `2476`), all of which bypass the async error-callback convention used throughout `validation.js`. Because JS `throw` inside a callback executed asynchronously (e.g., inside `conn.query(...)` result handlers) cannot be caught by any surrounding `try/catch` in the calling stack, and ocore's global `uncaughtException` handler intentionally re-throws to crash the process (with a comment "crash the process to avoid ending up in an inconsistent state"), this is a deliberate design decision that trades availability for consistency — but it means externally reachable malformed input can deterministically kill the node.

### Impact Explanation
This maps to the CVE's bug class: a low-privileged input source (here, a private-payment counterparty, analogous to the unprivileged ARM guest) can trigger an unhandled abort/exception that brings down the entire host process — a full denial of service of the wallet/node. In ocore terms, an attacker crafting a malformed private payment chain (for private, fixed-denomination assets) can cause the recipient's node to crash entirely, halting all of its unit processing (not merely rejecting the bad payment). Repeated crashes could be used to reliably deny service to a targeted wallet/node whenever it tries to receive private payments.

### Likelihood Explanation
Moderate-to-high for a targeted attack: constructing a private-asset transfer chain and choosing to omit/malform the `src_coin.denomination`/`amount`/`src_output` fields is straightforward for anyone controlling the sending side of a private payment (a normal capability of any private-payment counterparty), and this is exactly the malformed-payload scenario the surrounding code was clearly designed to reject gracefully via `cb(...)`, except for these specific fields which throw instead.

### Recommendation
Replace the `throw Error(...)` calls in the private-asset transfer branch of `validatePaymentInputsAndOutputs` (validation.js:2416-2424) — and the analogous throws in `checkForDoublespends` (validation.js:1673, 1688, 1692) and the src_output amount checks (validation.js:2458, 2476) — with calls to `callback(err)`/`cb(err)` so malformed externally-supplied private-payment data results in a normal validation error (`ifUnitError`/`ifError`) instead of an unhandled exception that crashes the whole node process.

### Proof of Concept
1. Attacker (private-payment sender) constructs a private, fixed-denomination asset transfer chain destined for a victim's wallet/node.
2. In the transfer message's private element/payload, the attacker omits the `denomination` or `amount` field of what would become `src_coin`, or omits the entire `src_output`.
3. Victim's node receives the private payment and calls `private_payment.validateAndSavePrivatePaymentChain` → `indivisible_asset.validateAndSavePrivatePaymentChain` → `validation.validate` → `validatePaymentInputsAndOutputs`.
4. Execution reaches the `transfer` branch for a private fixed-denomination asset at validation.js:2415-2424, finds `src_coin.denomination`/`amount` missing (or `src_output` missing), and executes `throw Error("no denomination in src coin")` (or similar).
5. This throw occurs inside an asynchronous callback chain and is not caught locally; it propagates to Node's `uncaughtException` handler in `network.js:4530`, which logs it and re-throws, terminating the victim's node process. [4](#0-3) [5](#0-4) [3](#0-2) [1](#0-0)

### Citations

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

**File:** private_payment.js (L35-45)
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
```

**File:** private_payment.js (L104-105)
```javascript
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
```
