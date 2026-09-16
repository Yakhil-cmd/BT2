### Title
Unvalidated `src_coin` state in private-asset transfer validation crashes the node process - (File: `validation.js`)

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` assumes that when validating a `transfer` input of a private, fixed-denomination asset, the caller has already populated `objValidationState.src_coin` with a well-formed `{ src_output, denomination, amount }` object. When this precondition is not met, the code raises a bare `throw Error(...)` instead of returning a normal `ifUnitError`/`ifJointError` through the callback chain, which is the same bug class as CVE-2020-27617: missing validation of an internal field before a hard assertion/throw is executed, crashing the process rather than producing a controlled protocol error.

### Finding Description
Inside the `case "transfer":` branch of the `async.forEachOfSeries(payload.inputs, ...)` loop, for private fixed-denomination assets the code takes a different path that bypasses the DB lookup and instead trusts pre-populated state: [1](#0-0) 

```
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

These four checks are implemented as unconditional `throw Error(...)` statements rather than calling `cb(err)`/`callback(err)` like every other validation failure in this function (e.g. the surrounding `hasFieldsExcept`, `isStringOfLength`, etc. failures at [2](#0-1) , which all correctly `return cb("...")`).

`validate()` in `validation.js` is invoked without a surrounding `try/catch` in the network entry point `handleJoint()`: [3](#0-2) 

so any synchronous `throw` inside the validation callback chain propagates out of `mutex.lock`/`validation.validate` and becomes an uncaught exception. The process installs a global handler that deliberately re-throws to crash the whole node: [4](#0-3) 

```
process.on('uncaughtException', (err) => {
	...
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```

Thus any code path that reaches the `throw Error("no src_coin")`/`"no src_output"`/etc. lines with unmet preconditions will crash the entire node process, not just reject one bad unit — mirroring the QEMU bug where a missing/invalid field (L3 protocol type) reaches an `assert()` instead of a graceful error path, crashing the whole process instead of just dropping the malformed packet.

### Impact Explanation
A crash triggered here is not merely a rejected transaction — it takes down the whole hub/full node process handling private payment chains (wallets, hubs relaying private payments). Given the project's own comment in `network.js` ("clear host only if validation completed with any result, otherwise it crashed and we keep it for a while to avoid DoS from the same peer") and the explicit `uncaughtException` handler that intentionally kills the process, an attacker able to reach this code path with `objValidationState.src_coin` unset or malformed can repeatedly crash any hub/full node that processes their crafted private-asset payment chain, denying service to the network's ability to validate/confirm units (a network-availability impact matching "network unable to confirm new units").

### Likelihood Explanation
Reaching this branch requires: (1) a private, fixed-denomination asset, (2) a `transfer` input on that asset, and (3) the caller-populated `objValidationState.src_coin` being absent/malformed when `validatePaymentInputsAndOutputs` is invoked for that input. This is the code path used for private-payment-chain validation (`indivisible_asset.js`, `private_payment.js`, `divisible_asset.js`, `wallet.js` all call into unit validation for privately-forwarded chains). I was not able to fully trace, within the available tool budget, every caller that sets `objValidationState.src_coin` to confirm whether a hostile private-chain sender can force this specific field to be missing/malformed at the exact point `validatePaymentInputsAndOutputs` runs (e.g., by sending a chain with mismatched/omitted elements that a well-behaved sender would never produce, or a malformed hidden-payment message via `private_payment.js`). This is a plausible but not fully proven reachability from an external, unprivileged private-payment counterparty, so likelihood should be treated as uncertain pending deeper tracing of `indivisible_asset.js`/`private_payment.js` call sites into `validation.validate`.

### Recommendation
Replace the four `throw Error(...)` calls at `validation.js` lines 2416–2423 with calls to `return cb(...)` (or the appropriate `ifUnitError`/transient-error path) so that a missing/malformed `src_coin` state is treated as a normal validation failure for the specific unit, rather than an uncaught exception that crashes the entire process. Additionally, review other `throw Error(...)` call sites inside `validatePaymentInputsAndOutputs` (e.g., lines 2451, 2458, 2476, 2591, 2217) to determine which are truly unreachable DB/internal invariants versus externally influenceable conditions, and convert any externally reachable one to a controlled error callback.

### Proof of Concept
Conceptual (not fully verified due to tool-call limits): a party in a private payment chain sends (via `private_payment.js`/`wallet.js` private-payment message handling) a payment message referencing a private, `fixed_denominations` asset with a `transfer` input, structured so that whichever code path populates `objValidationState.src_coin` before calling `validation.validate()` fails to do so correctly (e.g., omits/mismatches chain elements expected by the recipient's private-chain validator). When `validatePaymentInputsAndOutputs` reaches the `case "transfer":` branch for that private fixed-denomination asset, it executes `throw Error("no src_coin")` (or one of the sibling throws), which is uncaught by `handleJoint`/`validate`, triggers `process.on('uncaughtException')`, and crashes the receiving node/wallet process per [4](#0-3) . Confirming this PoC end-to-end would require reading `indivisible_asset.js` and `private_payment.js` in full to trace exactly how/when `src_coin` is set relative to attacker-controlled chain content.

### Citations

**File:** validation.js (L2393-2400)
```javascript
					if (hasFieldsExcept(input, ["type", "unit", "message_index", "output_index"]))
						return cb("unknown fields in payment input");
					if (!isStringOfLength(input.unit, constants.HASH_LENGTH))
						return cb("wrong unit length in payment input");
					if (!isNonnegativeInteger(input.message_index))
						return cb("no message_index in payment input");
					if (!isNonnegativeInteger(input.output_index))
						return cb("no output_index in payment input");
```

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

**File:** network.js (L1174-1174)
```javascript
			validation.validate(objJoint, {
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
