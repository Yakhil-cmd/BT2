### Title
Floating-point "integer overflow" in payment input/output summation allows loss of precision in balance checks - (File: validation.js)

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` accumulates `total_input` and `total_output` as plain JavaScript `Number` values while individually bounding each input/output amount only to `constants.MAX_CAP` (9e15), never to `Number.MAX_SAFE_INTEGER` (2^53‑1 ≈ 9.007e15). Because up to `MAX_INPUTS_PER_PAYMENT_MESSAGE` (128) inputs can each be up to `MAX_CAP`, the *sum* `total_input` can reach ~1.15e18 before it is ever range-checked, well past the point where IEEE‑754 doubles lose integer precision. This is the JS analog of the native integer-overflow bug class described in CVE-2020-6569 (an unchecked size/length computation exceeding the safe representable range, corrupting downstream state).

### Finding Description [1](#0-0) 
`total_input` starts at 0 with no incremental range check. [2](#0-1) 
For an `issue` input, `total_input += input.amount` is added, where `input.amount` is bounded only by `constants.MAX_CAP`: [3](#0-2) [4](#0-3) 
For `transfer` inputs, `total_input += src_output.amount`, where `src_output.amount` is itself a previously-validated, individually `MAX_CAP`-bounded output amount recorded in the DB.

`total_output`, by contrast, *is* checked after every addition inside the output loop and can therefore never leave the safe range: [5](#0-4) 

`total_input`, however, is only range-checked once, after the entire input loop completes: [6](#0-5) 

and the final balance check simply compares the two floats for strict equality: [7](#0-6) 

Because `MAX_CAP` (9e15) is defined close to `Number.MAX_SAFE_INTEGER` (~9.007e15): [8](#0-7) 

any payment message with more than ~2 large inputs (up to the `MAX_INPUTS_PER_PAYMENT_MESSAGE` limit of 128) whose individual amounts are each near `MAX_CAP` pushes `total_input`'s running sum past 2^53. Beyond that threshold, JS double-precision arithmetic silently rounds integer sums to the nearest representable value (gaps of 2, 4, 8, … as magnitude grows), so the computed `total_input` no longer necessarily equals the true integer sum of the individual, already-validated amounts that fund it.

The reachable attack surface is an ordinary, unprivileged unit author who defines an *uncapped, transferable* custom asset (`objAsset.cap` absent — no `is_private`/`fixed_denominations` needed): [9](#0-8) 
Since the asset is uncapped, the issuer can post many separate `issue` messages over time (each capped only by `MAX_CAP` per message, with unique `serial_number`), accumulating a large set of stored outputs. Later, a single payment message can reference up to 128 of these outputs as `transfer` inputs in one payload, driving `total_input`'s intermediate sum far past the 2^53 safe-integer boundary before the single post-loop `> MAX_CAP` check and the `total_input !== total_output` equality check are evaluated.

### Impact Explanation
If the rounding behavior can be engineered (by choosing the specific combination/order of large input amounts) so that the floating-point-rounded `total_input` coincides with a `total_output` that is deliberately crafted to be smaller than the true sum of consumed inputs (while `total_output` itself, being incrementally checked, safely stays ≤ `MAX_CAP` and fully precise), the validator would accept a payment whose real accounting is unbalanced. This is a supply-inflation / unauthorized-value-creation primitive for the affected custom asset — new value effectively appears in the recipient's spendable output without a corresponding decrease elsewhere, entirely from data supplied inside a single, self-composed unit that any wallet/AA-adjacent user can post.

### Likelihood Explanation
Exploitability requires: (1) defining or controlling an uncapped, transferable asset, (2) obtaining/issuing a set of large-valued outputs of that asset over time (each ≤ `MAX_CAP`, individually legal), and (3) crafting a payment message with a combination of up to 128 such inputs whose IEEE‑754 double summation rounds to a value matching a chosen `total_output`. This is a nontrivial but purely off-chain, deterministic computation (double-precision arithmetic is fully reproducible), so an attacker can precompute the exact input amounts needed to force a rounding collision before ever submitting the unit — no race condition, network position, or privileged role is required, only ordinary unit composition rights over an asset the attacker controls or has otherwise acquired sufficient issued outputs of.

### Recommendation
Perform all balance arithmetic in `validatePaymentInputsAndOutputs` (and any other place summing amounts capped only by `MAX_CAP`, e.g. `net_target_amount`/`total_amount` accumulation in `aa_composer.js` and `composer.js`) using an exact/arbitrary-precision integer type (e.g. `BigInt`) instead of native `Number`, or add an incremental check on every addition to `total_input` (mirroring the existing per-iteration check already applied to `total_output`) that rejects the unit the moment the running sum exceeds `Number.MAX_SAFE_INTEGER`, well before it can exceed `constants.MAX_CAP`. Additionally, lower `MAX_CAP` or reduce `MAX_INPUTS_PER_PAYMENT_MESSAGE` so that `MAX_CAP * MAX_INPUTS_PER_PAYMENT_MESSAGE` can never approach `Number.MAX_SAFE_INTEGER`.

### Proof of Concept
Conceptual outline (exact byte-for-byte PoC amounts would require running the V8 double-rounding arithmetic to find a colliding combination, which could not be executed in this read-only review):
1. Attacker defines a custom asset with no `cap`, `is_transferrable: true`.
2. Attacker issues many separate `issue` messages for that asset over time, each with `amount` close to `constants.MAX_CAP` (9e15) and a distinct `serial_number`, accumulating a large pool of confirmed, individually-valid outputs.
3. Attacker composes one payment message for that asset with up to `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` (128) `transfer` inputs drawn from that pool, chosen so the JS double summation of `total_input` (computed via repeated `total_input += src_output.amount` at `validation.js:2510`) rounds, due to IEEE‑754 precision loss past 2^53, to a value equal to a `total_output` the attacker sets on the outputs side (each output individually ≤ `MAX_CAP`, so `total_output` stays exact/within safe range per the check at `validation.js:2196`).
4. `validatePaymentInputsAndOutputs` accepts the unit at `validation.js:2611-2615` because `total_input === total_output` numerically, despite the true integer sum of the consumed inputs exceeding the true integer sum of the produced outputs — the difference is created out of the floating-point rounding gap, not from actual burned value.

### Citations

**File:** validation.js (L2136-2140)
```javascript
	var total_input = 0;
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
```

**File:** validation.js (L2195-2197)
```javascript
		total_output += output.amount;
		if (total_output > constants.MAX_CAP)
			return callback("total output too large: " + total_output);
```

**File:** validation.js (L2315-2318)
```javascript
					if (!isPositiveInteger(input.amount))
						return cb("amount must be positive");
					if (input.amount > constants.MAX_CAP)
						return cb("issue amount too large: " + input.amount)
```

**File:** validation.js (L2354-2354)
```javascript
					total_input += input.amount;
```

**File:** validation.js (L2510-2510)
```javascript
							total_input += src_output.amount;
```

**File:** validation.js (L2611-2612)
```javascript
			if (total_input > constants.MAX_CAP)
				return callback("total input too large: " + total_input);
```

**File:** validation.js (L2613-2615)
```javascript
			if (objAsset){
				if (total_input !== total_output)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output);
```

**File:** validation.js (L2725-2736)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");
```

**File:** constants.js (L57-57)
```javascript
exports.MAX_CAP = 9e15;
```
