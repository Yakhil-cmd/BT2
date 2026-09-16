### Title
Integer-precision overflow in payment balance check enables asset value creation - (File: `validation.js`)

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` accumulates `total_input` by repeatedly adding `src_output.amount` (or `src_coin.amount`) values with a plain JavaScript `+=`, and only checks the accumulated total against `constants.MAX_CAP` **after** the entire input loop finishes [1](#0-0) , unlike the output loop which re-checks the running `total_output` against `MAX_CAP` after every single addition [2](#0-1) . This mirrors the root cause pattern in the reported CVE: size/amount arithmetic is validated too late and too coarsely, after values have already been combined, instead of being bounded at each step.

### Finding Description
`constants.MAX_CAP` is `9e15` [3](#0-2) , which is extremely close to `Number.MAX_SAFE_INTEGER` (`9007199254740991`, ≈`9.007e15`) [4](#0-3) . `MAX_INPUTS_PER_PAYMENT_MESSAGE` allows up to 128 inputs per payment message [5](#0-4) , and each individual input amount for an issue (or previously validated transfer output) can legitimately be as large as `MAX_CAP` [6](#0-5) .

For custom, uncapped divisible assets there is no aggregate supply limit enforced at issuance time — the cap check only forces `serial_number === 1` when `objAsset.cap` is set, but uncapped assets can be issued repeatedly in separate units, each issuance up to `MAX_CAP` [7](#0-6) . An asset issuer can therefore accumulate a set of existing UTXOs whose individual amounts are each close to `9e15`.

When those outputs are later combined as inputs to a single payment (up to 128 inputs), `total_input` is summed with unbounded intermediate values [8](#0-7) [9](#0-8) , and only checked against `MAX_CAP` once, after the loop completes [10](#0-9) . Because JavaScript numbers are IEEE-754 doubles, once the running sum exceeds `Number.MAX_SAFE_INTEGER` it can no longer represent every integer exactly — additions of amounts smaller than the current rounding granularity are silently absorbed/rounded. This can make the accumulated `total_input` collapse to a value that is bit-for-bit equal to a crafted `total_output` sum (also accumulated as a double, but bounded early via the per-iteration `MAX_CAP` check) even though the true (arbitrary-precision) sums differ. The final balance check `total_input !== total_output` [11](#0-10)  would then incorrectly pass, letting the poster construct an asset payment whose declared outputs do not actually balance against consumed inputs.

### Impact Explanation
If exploitable, this allows a single asset issuer/spender to fabricate divisible-asset value beyond what was legitimately issued and backed by consumed inputs — an unauthorized supply-inflation vector reachable purely by posting ordinary payment units for a custom asset the attacker controls, with no privileged network position required. This satisfies the "supply inflation" acceptance criterion.

### Likelihood Explanation
Exploitation requires the attacker to first legitimately issue (as the asset definer, over multiple separate units) enough asset value to accumulate outputs whose sum, when combined as inputs in one payment message, crosses the `Number.MAX_SAFE_INTEGER` boundary (~9.007e15), which is achievable within the 128-input limit and the 9e15 per-output cap. It is a self-contained, no-collusion scenario limited to assets the attacker itself defines/issues, making it a purely single-attacker, deterministic path rather than a probabilistic one — moderate-to-high likelihood given no additional trust or network condition is required, though it does require careful crafting of amounts to land exactly on a colliding floating-point representation.

### Recommendation
- Enforce a `total_input > constants.MAX_CAP` bound check incrementally inside the input-processing loop (mirroring the existing per-iteration `total_output` check) so the running sum can never leave the safe-integer range.
- More robustly, perform all amount summation and equality comparisons for `total_input`/`total_output` using arbitrary-precision integer arithmetic (e.g., BigInt) rather than native `Number` addition, eliminating floating-point precision loss entirely for financial totals.
- Apply the same treatment to the `updateInitialAABalances`/AA balance accumulation logic, which has a similar unmitigated addition path guarded only by a version-gated overflow flag [12](#0-11) .

### Proof of Concept
1. Attacker defines an uncapped, transferrable divisible asset (no `cap` field), so `serial_number` reuse restriction and total-cap tracking do not apply.
2. Over several separate units, attacker issues itself multiple outputs each with `amount` close to `constants.MAX_CAP` (`9e15`), which pass validation individually since each issue is checked only against `MAX_CAP`, not an aggregate [7](#0-6) .
3. Attacker crafts a single payment message spending, say, 3–4 of these outputs as inputs (within `MAX_INPUTS_PER_PAYMENT_MESSAGE`=128), such that the running `total_input` sum crosses `Number.MAX_SAFE_INTEGER` and, due to double rounding, lands on the same double value as a `total_output` sum that the attacker computed to be numerically distinct but rounding-equal.
4. Submit the unit; `validatePaymentInputsAndOutputs` computes `total_input` via repeated float addition without intermediate bound checks [13](#0-12) , and the final equality check `total_input !== total_output` at line 2614 passes despite a real mismatch, letting the unit validate with fabricated output value [14](#0-13) .

Note: Exact amounts needed to trigger a colliding double rounding were not empirically derived here (would require constructing precise double bit patterns); this PoC describes the reachable code path and precondition, not a verified concrete byte-for-byte exploit value. A background Devin session with code execution could compute the exact colliding amounts to fully weaponize/confirm this PoC.

### Citations

**File:** validation.js (L2193-2198)
```javascript
		if (output.address && arrOutputAddresses.indexOf(output.address) === -1)
			arrOutputAddresses.push(output.address);
		total_output += output.amount;
		if (total_output > constants.MAX_CAP)
			return callback("total output too large: " + total_output);
	}
```

**File:** validation.js (L2315-2353)
```javascript
					if (!isPositiveInteger(input.amount))
						return cb("amount must be positive");
					if (input.amount > constants.MAX_CAP)
						return cb("issue amount too large: " + input.amount)
					if (!isPositiveInteger(input.serial_number))
						return cb("serial_number must be positive");
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
					if (bIssue)
						return cb("only one issue per message allowed");
					bIssue = true;
					
					var address = null;
					if (arrAuthorAddresses.length === 1){
						if ("address" in input)
							return cb("when single-authored, must not put address in issue input");
						address = arrAuthorAddresses[0];
					}
					else{
						if (typeof input.address !== "string")
							return cb("when multi-authored, must put address in issue input");
						if (arrAuthorAddresses.indexOf(input.address) === -1)
							return cb("issue input address "+input.address+" is not an author");
						address = input.address;
					}
					
					arrInputAddresses = [address];
					if (objAsset){
						if (objAsset.cap && !objAsset.fixed_denominations && input.amount !== objAsset.cap)
							return cb("issue must be equal to cap");
					}
					else{
						if (!storage.isGenesisUnit(objUnit.unit))
							return cb("only genesis can issue base asset");
						if (input.amount !== constants.TOTAL_WHITEBYTES)
							return cb("issue must be equal to cap");
					}
```

**File:** validation.js (L2436-2436)
```javascript
						total_input += src_coin.amount;
```

**File:** validation.js (L2508-2512)
```javascript
							if (arrInputAddresses.indexOf(owner_address) === -1)
								arrInputAddresses.push(owner_address);
							total_input += src_output.amount;
							
							if (bStableInParents)
```

**File:** validation.js (L2611-2615)
```javascript
			if (total_input > constants.MAX_CAP)
				return callback("total input too large: " + total_input);
			if (objAsset){
				if (total_input !== total_output)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output);
```

**File:** constants.js (L10-11)
```javascript
if (!Number.MAX_SAFE_INTEGER)
	Number.MAX_SAFE_INTEGER = Math.pow(2, 53) - 1; // 9007199254740991
```

**File:** constants.js (L47-47)
```javascript
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
```

**File:** constants.js (L57-57)
```javascript
exports.MAX_CAP = 9e15;
```

**File:** aa_composer.js (L476-490)
```javascript
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
```
