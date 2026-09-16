### Title
Asset `transfer_condition` can be bypassed by bundling a self-issue input in the same payment message - (File: `validation.js`)

### Summary
`validatePaymentInputsAndOutputs()` picks which asset spending condition to enforce (`issue_condition` vs `transfer_condition`) using a single message-wide `bIssue` flag, not per-input. Any unit poster who owns coins of an asset that allows open issuance (`issued_by_definer_only=false`) can attach a trivial self-issue input to the same payment message as a real transfer input, which flips `bIssue` to `true` for the whole message and causes the definer's `transfer_condition` to be skipped entirely for that transfer.

### Finding Description
Each `payment` message's inputs are processed by `validatePaymentInputsAndOutputs()` in `validation.js`. When an `issue`-type input is seen, `bIssue` is set to `true` for the entire message: [1](#0-0) 

Because an issue input must simply be `input_index === 0` ("issue must come first") and subsequent inputs may be ordinary `transfer` inputs from the same authors' outputs, a single message can legally mix one `issue` input with one or more `transfer` inputs: [2](#0-1) 

At the end of input processing, the condition that is evaluated against the *whole* payload is chosen solely by the message-level `bIssue` flag:

```
var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
``` [3](#0-2) 

If `bIssue` is `true` because of the tiny self-issue input, `objAsset.transfer_condition` is never evaluated, even though the bulk of the funds actually moved by the message come from `transfer` inputs, not the issue. This mirrors the Tapioca `multiHopBuyCollateral()` bug class: a single boolean/flag intended to gate one sub-operation (issuance) is reused to gate a combined operation (issuance + transfer), letting the attacker suppress the check meant for the larger, unauthorized-in-spirit sub-operation (the transfer) by supplying a cheap, always-available instance of the other sub-operation (a self-issue).

For assets that are not restricted to `issued_by_definer_only`, any address can freely add an issue input (uniqueness is keyed per `address + serial_number`, so it never collides with other issuers): [4](#0-3) 

The `owner_address` (spender) of the transfer input must still be a unit author (so a signature is still required for one's own funds), but this does not stop the attack: the vulnerability is not about spending someone else's coins, but about an asset owner evading a `transfer_condition` set by the asset definer (e.g. an oracle-gated restriction, destination whitelist, KYC/compliance rule, or any custom spending condition placed on the asset) simply by attaching an issue input to the transfer message.

### Impact Explanation
The asset definer's `transfer_condition` is a first-class part of the asset issuance and transfer-condition subsystem covered in scope. Bypassing it lets any holder of an openly-issuable asset move funds under conditions the definer explicitly intended to restrict (e.g. compliance/whitelist/oracle gating), defeating the purpose of `transfer_condition` for the entire class of non-`issued_by_definer_only` assets. This is a concrete violation of asset transfer conditions enforceable at the validation layer that every full node accepts as valid, so it also creates a systemic node-agreement risk: nodes rely on `transfer_condition` to reject non-compliant transfers, and this bug makes such transfers pass validation unconditionally.

### Likelihood Explanation
Any unprivileged unit poster holding coins of an openly-issuable asset (`issued_by_definer_only=false`) that has a `transfer_condition` defined can trigger this by simply adding a 1-unit issue input of the same asset to their transfer message — no special privilege, timing, or race condition is required.

### Recommendation
Track `bIssue` per input group / evaluate `issue_condition` and `transfer_condition` independently, or forbid mixing `issue` and `transfer` inputs of the same asset within one payment message. At minimum, when a message contains both an issue input and transfer inputs, both `issue_condition` (for the issued amount) and `transfer_condition` (for the transferred amount) must be evaluated and both satisfied.

### Proof of Concept
1. Define an asset `A` with `issued_by_definer_only: false` and a `transfer_condition` that restricts recipients (e.g. `["address", "WHITELISTED_ADDR"]` or an oracle-based condition).
2. Attacker (holder of asset `A` coins, not on the whitelist) composes a single `payment` message for asset `A` containing:
   - input[0]: `{type: "issue", amount: 1, serial_number: <unused>}` (self-issue, always allowed since `issued_by_definer_only=false`)
   - input[1..]: `transfer` inputs spending the attacker's existing `A` outputs
   - outputs: sending the transferred amount to a non-whitelisted address
3. In `validatePaymentInputsAndOutputs()`, `bIssue` becomes `true` due to input[0], so at the final check `arrCondition = objAsset.issue_condition` is evaluated instead of `objAsset.transfer_condition`.
4. If `issue_condition` is unset or more permissive than `transfer_condition`, the unit validates successfully and the transfer condition is fully bypassed.

### Citations

**File:** validation.js (L2311-2327)
```javascript
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
```

**File:** validation.js (L2366-2373)
```javascript
					if (objAsset){
						doubleSpendWhere += " AND serial_number=?";
						doubleSpendVars.push(input.serial_number);
					}
					if (objAsset && !objAsset.issued_by_definer_only){
						doubleSpendWhere += " AND address=?";
						doubleSpendVars.push(address);
					}
```

**File:** validation.js (L2388-2410)
```javascript
				case "transfer":
				//	if (objAsset)
				//		profiler2.start();
					if (bHaveHeadersComissions || bHaveWitnessings)
						return cb("all transfers must come before hc and witnessings");
					if (hasFieldsExcept(input, ["type", "unit", "message_index", "output_index"]))
						return cb("unknown fields in payment input");
					if (!isStringOfLength(input.unit, constants.HASH_LENGTH))
						return cb("wrong unit length in payment input");
					if (!isNonnegativeInteger(input.message_index))
						return cb("no message_index in payment input");
					if (!isNonnegativeInteger(input.output_index))
						return cb("no output_index in payment input");
					
					var input_key = (payload.asset || "base") + "-" + input.unit + "-" + input.message_index + "-" + input.output_index;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return cb("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
					
					doubleSpendWhere = "type=? AND src_unit=? AND src_message_index=? AND src_output_index=?";
					doubleSpendVars = [type, input.unit, input.message_index, input.output_index];
					if (conf.storage == "mysql")
						doubleSpendIndexMySQL = " FORCE INDEX(bySrcOutput) ";
```

**File:** validation.js (L2643-2658)
```javascript
					function(cb){
						var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
						if (!arrCondition)
							return cb();
						Definition.evaluateAssetCondition(
							conn, payload.asset, arrCondition, objUnit, objValidationState, 
							function(cond_err, bSatisfiesCondition){
								if (cond_err)
									return cb(cond_err);
								if (!bSatisfiesCondition)
									return cb("transfer or issue condition not satisfied");
								console.log("validatePaymentInputsAndOutputs with transfer/issue conditions done");
								cb();
							}
						);
					}
```
