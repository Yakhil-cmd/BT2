Based on my investigation, I found the analog in `aa_composer.js`'s `issueAsset` function within `completePaymentPayload`.

### Title
Unenforced Invariant `target_amount >= total_amount` Before Asset Issuance in AA `completePaymentPayload` Can Cause Negative `issue_amount` - (File: aa_composer.js)

### Summary
The `issueAsset` function inside `completePaymentPayload` (used when an AA's `payment` message doesn't have enough spendable outputs of an asset to cover the requested `target_amount`) computes `issue_amount = objAsset.cap || (target_amount - total_amount)` without verifying that `target_amount >= total_amount`. This mirrors the audit finding's root cause: a downstream subtraction (`limit - funded`, here `target_amount - total_amount`) is only safe under an invariant that is never explicitly enforced at the point of computation.

### Finding Description
In `aa_composer.js`'s `sendUnit` → `completePaymentPayload` → `issueAsset` (around lines 1175-1212), the code is only reached from `readUnstableOutputsSentByAAs`'s callback after `iterateUnspentOutputs` fails to find `bFound` in either the stable or unstable output pools [1](#0-0) . At that call site, `total_amount` reflects whatever unspent outputs were accumulated, and `target_amount` is derived from `payload.outputs` plus fee/size components that are recomputed as inputs are added [2](#0-1) . The invariant `target_amount >= total_amount` is implicitly assumed by `issueAsset`, exactly analogous to the reported bug's assumption `operator.limit >= operator.funded` being required before a subtraction, but it is never explicitly checked before computing `issue_amount = objAsset.cap || (target_amount - total_amount)` [3](#0-2) . If `total_amount` ever exceeds `target_amount` when `issueAsset` is invoked (e.g., because unstable AA-sent outputs accumulated by `iterateUnspentOutputs` overshoot the target due to a change output being pushed without breaking, or ordering/edge conditions in the oversize-fee recalculation as inputs are added), `issue_amount` becomes negative. `addIssueInput` then unconditionally pushes this negative-amount issue input into `payload.inputs` and adds it to `total_amount`, computing `change_amount = total_amount - target_amount` and only pushing a change output if that is positive [4](#0-3) .

### Impact Explanation
A negative `issue_amount` in a composed unit's issue input violates `isPositiveInteger(input.amount)`, which is enforced later in `validation.js`'s issue-input validation [5](#0-4) . Because this validation runs on the AA-generated response unit itself, the AA response would fail to validate/self-fail, disrupting the AA's payment message and potentially causing the AA to bounce or the response unit to be rejected — a node-visible processing failure for the AA that composed it, rather than a validated-but-wrong-state exploit. This differs from the original finding's silent underflow/revert in Solidity; in ocore's JS arithmetic, no numeric wraparound occurs, but the invariant gap can still produce a malformed unit and unexpected AA execution failure, which is a correctness/availability concern for the affected AA rather than a supply-inflation or double-spend bug.

### Likelihood Explanation
This code path executes only when an AA's payment message must issue new asset units to cover a shortfall, and only after both stable and unstable output pools are exhausted without reaching the target — a narrow, asset-issuing-AA-specific scenario reachable by any AA author's trigger design and asset configuration, not requiring any privileged actor. It requires a specific accumulation pattern where consumed unstable outputs sent by AAs overshoot the target amount before `issueAsset` is invoked.

### Recommendation
Add an explicit guard in `issueAsset` (or immediately before calling it) to assert/check `target_amount > total_amount` before computing `issue_amount = objAsset.cap || (target_amount - total_amount)`, returning an error via `cb2` if the invariant does not hold, mirroring the recommended fix of validating the relationship between the two values before performing the subtraction.

### Proof of Concept
Not concretely demonstrated — the search did not find a triggerable code path that guarantees `total_amount > target_amount` occurs in practice before `issueAsset` is called; `iterateUnspentOutputs` is generally designed to `break`/return once `bFound` becomes true, which structurally limits how far `total_amount` overshoots `target_amount`. A concrete unit sequence would need to be constructed and traced through `readStableOutputs`/`readUnstableOutputsSentByAAs` to confirm reachability of the negative-`issue_amount` state. [6](#0-5)

### Citations

**File:** aa_composer.js (L1090-1091)
```javascript
			var net_target_amount = payload.outputs.reduce(function (acc, output) { return acc + (output.amount || 0); }, size);
			let target_amount = net_target_amount + getOversizeFee(size);
```

**File:** aa_composer.js (L1102-1137)
```javascript
			function iterateUnspentOutputs(rows) {
				for (var i = 0; i < rows.length; i++){
					var row = rows[i];
					var input = { unit: row.unit, message_index: row.message_index, output_index: row.output_index };
					arrUsedOutputIds.push(row.output_id);
					arrConsumedOutputs.push({asset: asset || 'base', amount: row.amount});
					payload.inputs.push(input);
					total_amount += row.amount;
					if (is_base) {
						net_target_amount += FULL_TRANSFER_INPUT_SIZE;
						size += FULL_TRANSFER_INPUT_SIZE;
						target_amount = net_target_amount + getOversizeFee(size);
					}
					if (total_amount < target_amount)
						continue;
					if (total_amount === target_amount && payload.outputs.length > 0) {
						bFound = true;
						if (send_all_output)
							continue;
						else
							break;
					}
					var additional_output_size = is_base ? OUTPUT_SIZE + (bWithKeys ? OUTPUT_KEYS_SIZE : 0) : 0; // the same for send-all
					var change_amount = total_amount - (net_target_amount + additional_output_size + getOversizeFee(size + additional_output_size));
					if (change_amount > 0) {
						bFound = true;
						if (send_all_output) {
							console.log("change " + change_amount + ", storage_size " + storage_size);
							send_all_output.amount = change_amount;
						}
						else {
							payload.outputs.push({ address: address, amount: change_amount });
							break;
						}
					}
				}
```

**File:** aa_composer.js (L1179-1179)
```javascript
				var issue_amount = objAsset.cap || (target_amount - total_amount);
```

**File:** aa_composer.js (L1181-1192)
```javascript
				function addIssueInput(serial_number){
					var input = {
						type: "issue",
						amount: issue_amount,
						serial_number: serial_number
					};
					payload.inputs.unshift(input);
					total_amount += issue_amount;
					var change_amount = total_amount - target_amount;
					if (change_amount > 0)
						payload.outputs.push({ address: address, amount: change_amount });
					cb2();
```

**File:** aa_composer.js (L1223-1243)
```javascript
			readStableOutputs(function (rows) {
				iterateUnspentOutputs(rows);
				if (bFound && !send_all_output)
					return sortOutputsAndReturn();
				readUnstableOutputsSentByAAs(function (rows2) {
					iterateUnspentOutputs(rows2);
					if (bFound)
						return sortOutputsAndReturn();
					if (!asset)
						return cb('not enough funds for ' + target_amount + ' bytes');
					var bSelfIssueForSendAll = mci < (constants.bTestnet ? 2080483 : constants.aa3UpgradeMci);
					if (!bSelfIssueForSendAll && send_all_output && payload.outputs.length === 1) // send-all is the only output - don't issue for it
						return sortOutputsAndReturn();
					issueAsset(function (err) {
						if (err) {
							console.log("issue failed: " + err);
							return cb('not enough funds for ' + target_amount + ' of asset ' + asset);
						}
						sortOutputsAndReturn();
					});
				});
```

**File:** validation.js (L2315-2316)
```javascript
					if (!isPositiveInteger(input.amount))
						return cb("amount must be positive");
```
