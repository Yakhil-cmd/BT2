### Title
Quadratic-time O(n²) `arrInputKeys` linear scan enables unbounded-cost validation of AA-response payment inputs - (File: validation.js)

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` tracks "already used" input keys in a plain array, `objValidationState.arrInputKeys`, and checks for duplicates with `Array.prototype.indexOf()` — an O(n) linear scan — once per input. For ordinary, wallet-posted units this is bounded because `payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` (128) is rejected. However, that anti-spam cap is explicitly skipped for units emitted by Autonomous Agents: `if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)`. [1](#0-0) [2](#0-1) 

### Finding Description
Every input processed inside `validatePaymentInputsAndOutputs()` builds a `input_key` string and does:
```
if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
    return cb("input "+input_key+" already used");
objValidationState.arrInputKeys.push(input_key);
```
This pattern is repeated for `issue`, `transfer`, `headers_commission`/`witnessing` inputs, and also for `spend_proofs` in `validateMessage()`. [3](#0-2) [2](#0-1) [4](#0-3) [5](#0-4) 

`arrInputKeys` is shared across **all messages of the unit** (it's part of `objValidationState`, initialized once per unit and reused by every payment message via `validateMessages`/`validateMessage`), so the cost of validating the k-th input across the whole unit is O(k), giving O(n²) total time for n inputs in a unit — this is structurally the same quadratic-lookup bug class as `hash_search()` in the rsync report: an "already seen" set implemented with linear-time lookup instead of true O(1) hashing, whose cost is driven directly by attacker-controlled input count.

The number of messages per unit is capped by `constants.MAX_MESSAGES_PER_UNIT` (128) and this cap is *not* bypassed for AA units, but the per-message input cap (`MAX_INPUTS_PER_PAYMENT_MESSAGE`, 128) *is* explicitly bypassed for AA response units (`objValidationState.bAA`). This means a single payment message inside an AA-generated response unit can carry an arbitrarily large number of inputs (e.g., a huge number of tiny UTXOs picked up when the AA spends its balance), and validation of that message will run in O(n²) time proportional to the (attacker-influenced) number of coins held/spent by the AA address. [6](#0-5) 

### Impact Explanation
Since AA responses are triggered by ordinary, unprivileged units sent by anyone (an "AA trigger sender"), and an attacker can engineer conditions where the AA's address accumulates a very large number of small/dust outputs (e.g., by repeatedly sending many tiny trigger payments to the AA over time, or via an AA bounce/response cascade), a subsequent AA response spending many of those outputs in one payment message triggers a validation pass whose CPU cost scales quadratically with the input count. This can be used to stall or exhaust CPU on every full node that must validate/re-validate that unit (including during initial validation and later reprocessing/lookups), a network-wide sustained CPU DoS analogous to the rsync `hash_search()` issue — nodes may become unable to promptly validate/confirm new units while stuck processing the crafted AA response.

### Likelihood Explanation
Exploitability requires an attacker to first cause the AA's balance to be split across a very large number of small outputs (e.g. via many low-cost trigger transactions accumulating dust UTXOs at the AA address) and then trigger a response that consumes many of them in a single payment message — this is achievable purely by an unprivileged trigger sender over time and does not require compromising any node, peer, or hub, matching the "asset issuer / AA trigger sender" unprivileged-reachability requirement. The complexity to engineer a large enough input set is nontrivial but bounded only by economic cost (fees) and time, not by any protocol permission check, since the anti-spam input-count cap is explicitly disabled for AA units.

### Recommendation
Replace the array-based `arrInputKeys` (and the similarly linear `arrOutputAddresses` / `arrInputAddresses` / `arrConflictingUnits` lookups) with a `Set`/`Map` keyed by `input_key` for O(1) duplicate checks, and (more importantly) reinstate or add an explicit hard cap on the total number of payment inputs allowed within a single AA response message (or across the whole AA response unit) rather than fully exempting AA units from `MAX_INPUTS_PER_PAYMENT_MESSAGE`. If unlimited inputs are needed for legitimate AA use cases, enforce a much higher but still finite cap and ensure duplicate/double-spend tracking structures used during validation are all O(1) amortized per lookup.

### Proof of Concept
1. Deploy/trigger an AA whose bound address slowly accumulates thousands of tiny UTXOs (e.g., an AA that receives many small trigger payments over time, or is designed to fragment its balance).
2. Trigger a response from the AA that spends a very large number (e.g., tens of thousands) of these UTXOs as transfer inputs of a single payment message — allowed because `payload.inputs.length > MAX_INPUTS_PER_PAYMENT_MESSAGE` is skipped when `objValidationState.bAA` is true (validation.js:2137-2138).
3. When the resulting unit is validated (`validatePaymentInputsAndOutputs`, validation.js:2239 onward), each input triggers `objValidationState.arrInputKeys.indexOf(input_key)` over a `arrInputKeys` array that has grown to the same large size, producing O(n²) comparisons.
4. Measure validation wall-clock time on a node as `n` grows; observe superlinear (quadratic) growth consistent with the described DoS pattern, repeatable by any party able to influence the AA's UTXO fragmentation and trigger its response.

### Citations

**File:** validation.js (L1577-1579)
```javascript
			if (objValidationState.arrInputKeys.indexOf(objSpendProof.spend_proof) >= 0)
				return callback("spend proof "+objSpendProof.spend_proof+" already used");
			objValidationState.arrInputKeys.push(objSpendProof.spend_proof);
```

**File:** validation.js (L2128-2143)
```javascript
function validatePaymentInputsAndOutputs(conn, payload, objAsset, message_index, objUnit, objValidationState, callback){
	
//	if (objAsset)
//		profiler2.start();
	var denomination = payload.denomination || 1;
	var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
	var arrInputAddresses = []; // used for non-transferrable assets only
	var arrOutputAddresses = [];
	var total_input = 0;
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
	
	if (objAsset && objAsset.fixed_denominations && payload.inputs.length !== 1)
		return callback("fixed denominations payment must have 1 input");
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
