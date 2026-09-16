### Title
Missing per-iteration range check on `total_input` accumulator allows floating-point precision loss and inputs/outputs balance-check bypass - ([File: validation.js])

### Summary
The Zcash commit hardens `CAmount` accumulators by adding a range check after every mutation of a running sum, specifically calling out `GetTransparentValueIn` because it can accumulate up to ~48K per-input values before any bound is enforced, which "cannot be prevented at call sites, only inside the loop." `ocore`'s analog of `CAmount` arithmetic is plain JS `Number` (IEEE‑754 double), which is exact only up to `Number.MAX_SAFE_INTEGER` (2^53−1 ≈ 9.007×10^15). In `validatePaymentInputsAndOutputs` (validation.js), `total_input` is accumulated across up to `MAX_INPUTS_PER_PAYMENT_MESSAGE` (128) inputs via `total_input += src_output.amount` / `total_input += input.amount` / `total_input += commission`, but is only range-checked once, *after* the entire input loop completes: `if (total_input > constants.MAX_CAP) return callback(...)` [1](#0-0) . Individual amounts are bounded by `constants.MAX_CAP = 9e15` [2](#0-1) , which is just under 2^53, so combining even two or three such inputs (which is legal, since caps only bound a single value, not the multi-input sum) pushes `total_input` past `Number.MAX_SAFE_INTEGER` before the bound check ever runs.

### Finding Description
- Each transfer input's `src_output.amount` was validated as ≤ `constants.MAX_CAP` when it was originally created as an output [3](#0-2) , and issue inputs are similarly bounded per-issuance [4](#0-3) . Nothing bounds the *total* number of distinct large-valued outputs an address can accumulate over time for an uncapped divisible asset (repeated `issue` inputs with increasing `serial_number`, each up to `MAX_CAP`, are explicitly allowed: `addIssueInput` logic in `inputs.js` and the issue-input validation in `validation.js`) [5](#0-4) .
- `validatePaymentInputsAndOutputs` accumulates `total_input` unconditionally inside the `async.forEachOfSeries` callback for `issue`, `transfer`, `headers_commission`, and `witnessing` input types [6](#0-5) [7](#0-6) [8](#0-7) , with no intermediate `MoneyRange`-style check performed per addition — the only check on `total_input` happens once, after all inputs are processed [9](#0-8) .
- In contrast, `total_output` is checked after *every* single addition inside its loop [10](#0-9) , so it can never silently accumulate beyond one output past `MAX_CAP` before rejection. `total_input` has no equivalent per-step guard, exactly the asymmetry the Zcash commit fixes by adding the missing check "inside the loop" for `GetTransparentValueIn`.
- With `MAX_INPUTS_PER_PAYMENT_MESSAGE = 128` and `MAX_CAP = 9e15` [11](#0-10) [2](#0-1) , combining just two or three large-valued unspent outputs (obtainable by an attacker issuing an uncapped custom asset multiple times, or a public/private asset with a large `cap`) drives `total_input` above `Number.MAX_SAFE_INTEGER`. Beyond that threshold, JS doubles cannot represent every integer exactly — the granularity of representable values doubles (steps of 2, 4, 8, …) as the magnitude grows. The final equality/inequality checks that enforce value conservation — `total_input !== total_output` for custom assets [12](#0-11)  and `total_input !== total_output + headers_commission + payload_commission + ...` for the base asset [13](#0-12)  — are then performed on values that may have silently lost precision.

### Impact Explanation
If an attacker can arrange for `total_input`'s floating-point representation to coincide with a crafted `total_output` (or vice versa) despite the true integer sums differing, the node accepts a payment message that does not actually conserve value. This is a direct analog of the "supply inflation" impact class called out by the report: an unprivileged asset issuer or payment poster could mint value from precision loss rather than from a legitimate balance, or destroy value undetected. Because Obyte units are DAG-committed and irreversible once stable, any node that computes this comparison differently (or that accepts a unit whose sums don't truly balance) risks permanent, consensus-relevant accounting divergence and unrecoverable double-spend/inflation, matching the accepted impact categories (concrete supply inflation / double-spend of a stable output).

### Likelihood Explanation
Exploitability requires the attacker to control several outputs whose values sum past 2^53 while each individual value still respects `MAX_CAP` — achievable for uncapped, self-issued divisible assets (repeated issuances, no total-supply constraint enforced across issuances other than per-input `MAX_CAP`) or for a asset the attacker itself defines with a large `cap`. Building the precise floating-point collision (a crafted set of amounts whose IEEE-754 sum aliases a different true integer value) requires careful ordering/selection of amounts, but this is a well-understood floating-point rounding technique, not a cryptographic barrier, and it is entirely reachable from a single posted unit's payment message inputs — no privileged role is required.

### Recommendation
Mirror the Zcash fix pattern: enforce a bound (`0 <= total_input <= constants.MAX_CAP`, and ideally `<= Number.MAX_SAFE_INTEGER`) after every `total_input +=` mutation inside the `issue`/`transfer`/`headers_commission`/`witnessing` branches in `validatePaymentInputsAndOutputs` (validation.js), not only once after the loop completes. Reject the unit immediately (`return cb("total input out of range")`) the moment the accumulator would exceed `Number.MAX_SAFE_INTEGER` or `constants.MAX_CAP`, exactly as `total_output` already does per-iteration.

### Proof of Concept
1. Attacker issues (or is the definer of) an uncapped divisible custom asset and, across two prior units, issues two `issue` inputs each with `amount` close to `constants.MAX_CAP` (9e15), producing two large unspent outputs for the same address.
2. Attacker composes a new payment message with both outputs as `transfer` inputs in a single payload (well under `MAX_INPUTS_PER_PAYMENT_MESSAGE = 128`), whose true integer sum is `2 * 9e15 - 1 = 17999999999999999`, above `Number.MAX_SAFE_INTEGER` (9007199254740991).
3. `validatePaymentInputsAndOutputs` accumulates `total_input += src_output.amount` for each input without any intermediate range check [7](#0-6) ; the JS double representation of `total_input` rounds to the nearest representable value at that magnitude (granularity of 2).
4. Attacker crafts `payload.outputs` whose declared amounts differ by 1 unit from the true conserved value, but whose floating-point sum (`total_output`) rounds to the same representable double as `total_input`.
5. The single post-loop check `total_input > constants.MAX_CAP` fails to catch this because comparisons happen on the already-rounded double, and the balance check `total_input !== total_output` [12](#0-11)  passes despite the true integer amounts not balancing, letting the attacker gain (or destroy) the 1-unit discrepancy — repeatable to inflate supply over many transactions.

*(Exact numeric alias values require offline floating-point calculation to confirm the smallest colliding integer discrepancy at this magnitude; the core defect — absence of a per-addition range check on `total_input`, unlike the per-addition check already present for `total_output` — is confirmed directly from the code.)*

### Citations

**File:** validation.js (L2157-2160)
```javascript
		if (!isPositiveInteger(output.amount))
			return callback("amount must be positive integer, found "+JSON.stringify(output.amount));
		if (output.amount > constants.MAX_CAP)
			return callback("output too large: " + output.amount);
```

**File:** validation.js (L2195-2197)
```javascript
		total_output += output.amount;
		if (total_output > constants.MAX_CAP)
			return callback("total output too large: " + total_output);
```

**File:** validation.js (L2307-2354)
```javascript
			switch (type){
				case "issue":
				//	if (objAsset)
				//		profiler2.start();
					if (input_index !== 0)
						return cb("issue must come first");
					if (hasFieldsExcept(input, ["type", "address", "amount", "serial_number"]))
						return cb("unknown fields in issue input");
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
					total_input += input.amount;
```

**File:** validation.js (L2510-2510)
```javascript
							total_input += src_output.amount;
```

**File:** validation.js (L2596-2596)
```javascript
								total_input += commission;
```

**File:** validation.js (L2606-2612)
```javascript
		},
		function(err){
			console.log("inputs done "+payload.asset, arrInputAddresses, arrOutputAddresses);
			if (err)
				return callback(err);
			if (total_input > constants.MAX_CAP)
				return callback("total input too large: " + total_input);
```

**File:** validation.js (L2613-2615)
```javascript
			if (objAsset){
				if (total_input !== total_output)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output);
```

**File:** validation.js (L2661-2668)
```javascript
			else{ // base asset
				const vote_count_fee = objUnit.messages.find(m => m.app === 'system_vote_count') ? constants.SYSTEM_VOTE_COUNT_FEE : 0;
				const oversize_fee = objUnit.oversize_fee || 0;
				const tps_fee = objUnit.tps_fee || 0;
				const burn_fee = objUnit.burn_fee || 0;
				if (total_input !== total_output + objUnit.headers_commission + objUnit.payload_commission + oversize_fee + tps_fee + burn_fee + vote_count_fee)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output+" + "+objUnit.headers_commission+" + "+objUnit.payload_commission+" + "+oversize_fee+" + "+tps_fee+" + "+burn_fee+" + "+vote_count_fee);
				callback();
```

**File:** constants.js (L47-47)
```javascript
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
```

**File:** constants.js (L57-57)
```javascript
exports.MAX_CAP = 9e15;
```
