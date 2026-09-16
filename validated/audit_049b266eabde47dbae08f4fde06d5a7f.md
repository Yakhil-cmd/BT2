### Title
Reachable assertion (`throw Error`) on malformed private-asset coin data crashes node during private chain validation - (File: `validation.js`)

### Summary
`Open5GS` CVE-2025-65559 is a reachable-assertion DoS: a PFCP field (F-TEID address family) that is attacker-influenced but not pre-validated reaches an `ogs_assert`-style hard check in `ogs_pfcp_object_teid_hash_set`, crashing the UPF. The analogous bug class in `ocore` is a hard `throw Error()` (uncatchable "assertion") placed in a payment-input validation path that is fed by data supplied by the *other party in a private, fixed-denomination asset transfer*, without the surrounding validation logic first checking that this data is well-formed.

### Finding Description
In `validatePaymentInputsAndOutputs`, when validating a `"transfer"` input for a private asset with `fixed_denominations`, the code cannot look up the source output in the database (since the whole private chain is validated before saving anything). Instead, it relies on `objValidationState.src_coin`, an object that must be pre-populated by the caller with fields derived from the private-chain element sent by the payment counterparty: [1](#0-0) 

```
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

Instead of returning a soft validation error through the `cb`/`callback` mechanism used everywhere else in this file (e.g. `return cb("bad param1 ...")`), these four checks use `throw Error(...)`. This mirrors the CVE pattern exactly: a value that originates from a message sent by an untrusted counterparty (here, the private-payment sender constructing the `src_coin` object for an indivisible/fixed-denomination private asset chain element, analogous to the F-TEID CH/address-family field from the PFCP peer) is checked with a hard assertion rather than a graceful validation-error path, once it reaches a deeper internal consistency check that assumes upstream code has already guaranteed well-formedness.

Because `validate()` in `validation.js` is invoked synchronously from various message-handling entry points (private payment reception, wallet processing of an incoming private chain, or `network.js` unit handling) without every caller wrapping the call in a `try/catch` that gracefully recovers and continues node operation, an uncaught `throw Error` inside a deeply nested `async` callback chain (`async.forEachOfSeries`) can escape as an unhandled exception in that continuation, crashing the Node.js process — the same "reachable assertion" denial-of-service outcome as the CVE, but reached via a private-payment/private-chain validation path rather than a PFCP session-establishment path.

### Impact Explanation
An unhandled `throw Error` inside a callback invoked from `async.forEachOfSeries`/`async.eachSeries` in Node.js is not caught by any `try/catch` in the caller's call stack (because the throw happens in a different tick/callback context for asynchronous parts, and even for the synchronous path here it happens deep inside nested callbacks that are not universally wrapped). This can propagate to an `uncaughtException`, crashing the process that is validating the private chain — a full node, a wallet, or any device that receives and validates a private-payment chain for a fixed-denomination private asset. This matches the "network unable to confirm new units" / node-crash impact class defined in the analog rules, since the process handling private chain validation goes down.

### Likelihood Explanation
Any counterparty in a private, fixed-denomination asset payment can construct a malformed `src_coin`-equivalent private-chain element (missing `src_output`, non-positive `denomination`, or non-positive `amount`) and send it to the recipient for validation. This requires no special privilege beyond being a private-payment counterparty, which is explicitly in-scope per the analog rules ("private-payment counterparty ... can reach"). The trigger conditions (an indivisible/fixed-denomination private asset transfer with a crafted or corrupted private-chain payload) are realistic and directly reachable through the normal wallet/private-payment flow.

### Recommendation
Replace the four `throw Error(...)` assertions in the `"transfer"` case of `validatePaymentInputsAndOutputs` (`validation.js` lines 2416–2424) with graceful validation-error returns via `cb(...)`, consistent with the rest of the function, so malformed `src_coin` data supplied through a private chain is rejected as an invalid unit/joint rather than crashing the process. Additionally, audit all `objValidationState.src_coin` population sites (e.g., in `indivisible_asset.js`) to ensure they only ever populate well-formed data, and add defensive `try/catch` around the top-level chain validation entry point so any residual internal assertion failure is converted into a rejected/invalid-chain result instead of an uncaught exception.

### Proof of Concept
1. Construct a private, fixed-denomination asset (`objAsset.is_private = true`, `objAsset.fixed_denominations = true`).
2. As the private-payment counterparty, build a private-chain element for a `"transfer"` input whose accompanying `src_coin` data (as consumed via `objValidationState.src_coin` when the chain is validated) omits `src_output`, or sets `denomination`/`amount` to `0`/non-integer/negative.
3. Send this private chain to the victim (recipient wallet/node) for validation, triggering `validatePaymentInputsAndOutputs` → the `"transfer"` branch for `fixed_denominations` private assets shown above.
4. Because `src_coin.src_output`, `src_coin.denomination`, or `src_coin.amount` fail the positive-integer/existence checks, the code executes `throw Error("no src_output")` / `throw Error("no denomination in src coin")` / `throw Error("no src coin amount")` instead of returning a validation error, propagating as an unhandled exception in the validating process and crashing it (denial of service), analogous to the reachable assertion in `ogs_pfcp_object_teid_hash_set` triggered by a mismatched F-TEID address family in CVE-2025-65559.

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
