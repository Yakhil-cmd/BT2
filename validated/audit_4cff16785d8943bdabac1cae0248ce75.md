### Title
Uncontrolled Resource Consumption via Quadratic `arrInputKeys.indexOf` Scan During Payment/Spend-Proof Validation - ([File: validation.js])

### Summary
`validation.js` maintains a single shared array, `objValidationState.arrInputKeys`, that accumulates a string key for every payment input, issue input, header-commission/witnessing input, and spend-proof across *all* messages of a unit. Before every push, the code performs `objValidationState.arrInputKeys.indexOf(input_key)` — a linear scan of the entire array so far — to detect duplicate keys. Because this scan-then-push pattern is executed once per input/spend-proof and the array is never deduplicated or backed by a Set/hash-map, the total validation cost for a single unit grows as O(n²) in the number of inputs the attacker packs into that unit, exactly the same complexity class as the urllib3 `_encode_invalid_chars` bug (unbounded linear array scanned repeatedly instead of O(1) hash lookup).

### Finding Description
The vulnerable pattern recurs at multiple points in `validation.js`:

- Payment "transfer" inputs: [1](#0-0) 
- Payment "issue" inputs: [2](#0-1) 
- Headers-commission / witnessing inputs: [3](#0-2) 
- Spend proofs (private payments): [4](#0-3) 

`objValidationState` — and therefore `arrInputKeys` — is created once per unit and passed through `validateMessages` → `validateMessage` → `validatePaymentInputsAndOutputs` for every message in the unit, so the array is never reset between messages: [5](#0-4) . A single unit can contain up to `constants.MAX_MESSAGES_PER_UNIT` messages, and each payment message can carry many inputs/spend-proofs (spend-proofs bounded per-message by `MAX_SPEND_PROOFS_PER_MESSAGE`, but inputs are only implicitly bounded by the overall unit byte-size limit `MAX_UNIT_LENGTH`). As the attacker adds more (message, input) pairs, each new input triggers an `Array.prototype.indexOf` scan over an ever-growing array before being appended, producing classic O(n²) behavior identical in shape to the urllib3 CVE-2020-7212 root cause (unbounded, non-deduplicated array checked with a linear scan for every new element).

### Impact Explanation
Every full node that receives and validates the unit pays this same O(n²) validation cost. An attacker who is simply an unprivileged unit poster (no special network position or privileged key needed) can construct a single, protocol-valid unit that maximizes the number of inputs/spend-proofs across its messages, forcing all validating nodes to spend disproportionate CPU time in `validatePaymentInputsAndOutputs`/`validateSpendProofs` for that one unit. Because unit validation sits directly on the path to DAG inclusion and stability determination, sufficiently expensive validation work on crafted units can degrade the ability of the network to timely validate and confirm new units, which maps to the "network unable to confirm new units in a timely way" impact category permitted by the rules.

### Likelihood Explanation
The vector requires no special access — only the ability to post a unit — which is the same threat model as “unprivileged unit poster” explicitly in scope. Because the check is on the natural validation path for every payment/spend-proof input, no crafted malformed data or exploit of a parsing bug is needed; only cardinality of legitimate-looking inputs matters, making this straightforward to trigger deterministically.

### Recommendation
Replace the linear array `arrInputKeys` with a `Set` (or plain object used as a hash-map) for O(1) membership checks and insertion, eliminating the deduplication being O(n) per insertion. This mirrors the actual urllib3 fix (deduplicate before doing per-key work) and removes the quadratic blowup while preserving identical duplicate-detection semantics.

### Proof of Concept
1. Construct a unit with the maximum permitted number of payment messages (`MAX_MESSAGES_PER_UNIT`), each containing as many distinct "transfer" inputs as fit within `MAX_UNIT_LENGTH`.
2. Ensure each input references a distinct, validly-spendable prior output so the unit is otherwise fully valid and not rejected early for unrelated reasons.
3. Submit the unit to a node/hub. During `validatePaymentInputsAndOutputs`, each of the N inputs across the unit's messages triggers `objValidationState.arrInputKeys.indexOf(input_key)` over the (currently up to N-1) accumulated keys before the push at [1](#0-0) , yielding O(N²) string-array scans for validating this single unit, compared to O(N) with a Set-based check.
4. Compare CPU time/latency of validating this maximal-input unit versus a similarly-sized unit with the inputs spread across many small units, demonstrating the disproportionate, quadratic cost concentrated on a single validation call.

### Citations

**File:** validation.js (L1518-1531)
```javascript
	async.forEachOfSeries(
		arrSortedMessages, 
		function({ objMessage, message_index }, _sorted_idx, cb){
			validateMessage(conn, objMessage, message_index, objUnit, objValidationState, cb); 
		}, 
		function(err){
			if (err)
				return callback(err);
			if (!objValidationState.bHasBasePayment)
				return callback("no base payment message");
			callback();
		}
	);
}
```

**File:** validation.js (L1577-1579)
```javascript
			if (objValidationState.arrInputKeys.indexOf(objSpendProof.spend_proof) >= 0)
				return callback("spend proof "+objSpendProof.spend_proof+" already used");
			objValidationState.arrInputKeys.push(objSpendProof.spend_proof);
```

**File:** validation.js (L2356-2359)
```javascript
					var input_key = (payload.asset || "base") + "-" + denomination + "-" + address + "-" + input.serial_number;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return callback("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
```

**File:** validation.js (L2402-2405)
```javascript
					var input_key = (payload.asset || "base") + "-" + input.unit + "-" + input.message_index + "-" + input.output_index;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return cb("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
```

**File:** validation.js (L2569-2572)
```javascript
					var input_key = type + "-" + address;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return cb("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
```
