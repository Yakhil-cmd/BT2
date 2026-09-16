### Title
Attacker-triggerable `throw Error` in indivisible-asset private-payment validation crashes the validating node instead of rejecting the unit - ([File: validation.js])

### Summary
The Linux CVE fixes a pattern where a corruption/sanity condition that *can* legitimately be hit with attacker-supplied (corrupted) input was handled with a hard `WARN_ON()`/unrecoverable path instead of returning a normal error. The analogous anti-pattern in `ocore` is using `throw Error(...)` for "should never happen" sanity checks inside the unit-validation code path, where the checked condition is actually influenced by data supplied through a private-payment chain that a counterparty controls.

### Finding Description
In `validatePaymentInputsAndOutputs()` (`validation.js`), when validating a `transfer` input for a private, fixed-denomination asset, the code assumes `objValidationState.src_coin` and its sub-fields have already been populated correctly and throws a hard `Error` if not, rather than returning a normal validation error via `cb(...)`: [1](#0-0) 

`objValidationState.src_coin` is populated by the private-payment chain validation logic (`indivisible_asset.js`, invoked when a wallet receives a private-payment chain from a counterparty) before `validatePaymentInputsAndOutputs` is called for each element of that chain. Because the entire private-payment chain, including `denomination`, `amount`, and `src_output`, is supplied by an untrusted counterparty (private payments are p2p-exchanged, not broadcast, and are only checked by the receiving wallet at this point), a maliciously crafted or malformed chain element can cause `src_coin` or its fields to be missing/malformed when this code path is reached, since the earlier population step does not guarantee these invariants under adversarial input.

Unlike the rest of `validatePaymentInputsAndOutputs`, which converts bad input into a validation error string via `return cb("...")` — which safely propagates to `ifUnitError`/`ifJointError` callbacks and simply rejects the unit — this branch uses `throw Error(...)`. An uncaught `Error` thrown inside the async validation flow is not caught by the `async.series`/`async.eachSeries` control flow used throughout `validation.js`, and results in an unhandled exception that crashes the Node.js process handling the private payment (analogous to the kernel's `WARN_ON()`, which is a "die instead of gracefully reject" response to attacker-reachable bad state).

### Impact Explanation
A wallet or hub processing an incoming private payment chain for a fixed-denomination private asset can be crashed by a single malformed/malicious private-payment element that fails to satisfy the `src_coin` invariants assumed at this check. This is a denial-of-service against the specific node handling the private payment (the private-payment counterparty's own wallet/hub process), preventing it from continuing normal operation (processing further units, including confirming other transactions) until restarted — matching the "network unable to confirm new units" impact class for the affected node.

### Likelihood Explanation
Reaching this code requires only that an attacker act as a private-payment counterparty and send a crafted private-payment chain for a private, fixed-denomination asset (e.g., a blackbytes-like asset) to the victim's wallet; this is a normal, unprivileged wallet interaction (`validateAndSavePrivatePaymentChain` in `indivisible_asset.js` feeds into `validation.validate`). No special privileges beyond being a payment counterparty are needed, making this readily reachable, though it requires the victim to accept an inbound private payment.

### Recommendation
Replace the `throw Error("no src_coin")` / `"no src_output"` / `"no denomination in src coin"` / `"no src coin amount"` checks at `validation.js:2416-2424` with normal validation-error returns (`return cb("...")`), consistent with the rest of the function, so malformed/corrupted private-payment chain data is rejected as an ordinary validation failure instead of crashing the process. Audit other `throw Error` sanity checks in `validation.js` and `definition.js` that sit on paths reachable from externally supplied units, private-payment chains, or AA triggers, and convert any that depend on untrusted input into recoverable `cb(err)` returns.

### Proof of Concept
1. Attacker sends a private-payment chain (via the wallet-to-wallet private payment protocol) for a private, fixed-denomination asset to a victim wallet, using `indivisible_asset.validateAndSavePrivatePaymentChain`.
2. The attacker crafts the chain such that `objValidationState.src_coin` is left unset or missing `src_output`/`denomination`/`amount` when the victim's validation reaches the `transfer` input case for that private asset in `validatePaymentInputsAndOutputs` at `validation.js:2415-2424`.
3. The `throw Error(...)` executes inside the async validation chain, is not caught, and crashes the victim's Node.js process, denying it the ability to process further units/payments until manually restarted. [2](#0-1)

### Citations

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
