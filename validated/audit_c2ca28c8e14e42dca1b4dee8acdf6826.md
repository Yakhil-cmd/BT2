### Title
AA asset outputs bypass dust-size and input-count limits, allowing unbounded input accumulation when the AA spends the asset - ([File: aa_composer.js])

### Summary
The reported bug class is: a spam/DoS limit enforced at one entry point (`sendQuote`) is silently bypassed at another entry point (partial fill), letting an attacker accumulate an unbounded number of small pending records that are later processed in a loop-heavy critical operation (liquidation), causing gas exhaustion/DoS. The analogous root cause exists in ocore's AA payment-composition and validation code: dust-size filtering that protects AAs from spam is applied only to base-asset outputs, not to custom-asset outputs, and the general per-message input-count cap is explicitly disabled for AA-generated units.

### Finding Description
When an AA needs to compose a payment response, it collects unspent outputs it owns via `readStableOutputs`/`readUnstableOutputsSentByAAs` in `aa_composer.js`. For the base asset, a dust-size filter is applied: [1](#0-0) 
The comment explicitly states the purpose: "byte outputs less than 60 bytes ... are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond." However, for any non-base (custom) asset, the `amount>=FULL_TRANSFER_INPUT_SIZE` condition is omitted entirely — the query only filters `asset=?` with no minimum amount: [2](#0-1) 
The same asymmetry exists in `readUnstableOutputsSentByAAs`: [3](#0-2) 

Separately, when constructing the payment message, `iterateUnspentOutputs` walks the returned rows and unconditionally pushes each one into `payload.inputs` until the target amount is reached: [4](#0-3) 

Normally, `validatePaymentInputsAndOutputs` in `validation.js` caps the number of inputs per payment message via `MAX_INPUTS_PER_PAYMENT_MESSAGE`, but this check is explicitly skipped for AA-generated units: [5](#0-4) 
Likewise, the overall unit-size cap (`MAX_UNIT_LENGTH`) is skipped for AA units: [6](#0-5) 

Combining these three facts: (1) any unprivileged unit poster can send an unlimited number of tiny custom-asset outputs to an AA address (the dust filter that would normally block this only applies to the base asset), (2) when the AA is subsequently triggered to spend that asset (e.g., forwarding received funds, or its own logic issuing a payment in that asset), `iterateUnspentOutputs` will greedily consume every one of those dust outputs as separate inputs, and (3) neither `MAX_INPUTS_PER_PAYMENT_MESSAGE` nor `MAX_UNIT_LENGTH` bound the resulting message/unit for AA-generated units. This mirrors the Sherlock finding's structure exactly: a limit that exists and is enforced at one code path (regular, non-AA sender: dust filter + input cap) is silently absent on the analogous AA/asset code path, letting the attacker force an unboundedly large collection to be processed by size-unaware logic.

### Impact Explanation
An attacker can send thousands (or more) of dust-amount outputs of a chosen custom asset to a target AA address at negligible cost (custom-asset outputs have no minimum-amount validation requirement analogous to the base-asset dust filter). Any subsequent AA response that needs to pay out in that asset will be forced by `iterateUnspentOutputs` to include all of these dust inputs as `payload.inputs`, because there is no cap (`MAX_INPUTS_PER_PAYMENT_MESSAGE` is bypassed for AA units) and no size cap (`MAX_UNIT_LENGTH` is bypassed for AA units) that would otherwise force it to stop early or reject the oversized response. Consequences include:
- The AA's response-generation and validation work (`validatePaymentInputsAndOutputs`, `checkInputDoubleSpend` per input, `updateFinalAABalances`) scales linearly (or worse, given the double-spend check queries per input) with the number of attacker-controlled dust inputs, which must be processed by every full node validating and writing the resulting response unit during main-chain stabilization — a computation-heavy, per-input DB-query loop analogous to the reported liquidation for-loop gas blowup.
- Because the AA is forced to consume (and thus "spend") all outstanding dust outputs of that asset whenever it tries to pay out any amount of it, an attacker can effectively freeze or degrade the AA's ability to respond promptly/cheaply, and can inflate the size/processing cost of AA-generated units network-wide, since these units are exempt from `MAX_UNIT_LENGTH` and thus have no upper bound to fail gracefully.
- This can result in AA fund/response processing becoming impractically expensive or stalling stabilization-time processing for units that must be handled synchronously as part of main-chain advancement, matching the "network unable to confirm new units" / "AA fund loss or freezing" impact classes.

### Likelihood Explanation
Likelihood is Medium-High: creating and sending many small custom-asset outputs to a known AA address requires only ordinary, cheap `payment` messages from an unprivileged sender — no special privileges, and only nominal per-unit fees are required (unlike base-asset dust, which is explicitly filtered because it is known to be exploitable). The attacker needs the AA to receive/hold that asset and to trigger a payout of it, which is a common AA pattern (e.g., swap/exchange AAs, token-forwarding AAs). This is realistically triggerable by any unit poster.

### Recommendation
- Apply the same dust-size filtering used for base-asset outputs (`amount>=FULL_TRANSFER_INPUT_SIZE`) to custom-asset outputs in both `readStableOutputs` and `readUnstableOutputsSentByAAs`, using an asset-appropriate minimum threshold.
- Enforce `MAX_INPUTS_PER_PAYMENT_MESSAGE` (or an AA-specific but still bounded cap) for AA-generated payment messages instead of exempting `objValidationState.bAA` entirely.
- Consider re-enabling `MAX_UNIT_LENGTH` enforcement for AA units, or a comparable cap, so a pathological accumulation cannot silently balloon unit size processed by every node.

### Proof of Concept
1. Deploy or identify a target AA that, per its bytecode logic, forwards or pays out a custom asset `X` to callers (a common pattern for exchange/vault-style AAs).
2. As an unprivileged attacker, issue asset `X` (or acquire it cheaply) and send a large number (e.g., thousands) of 1-unit-amount `X` outputs to the AA's address across many payment units — this passes validation freely since no dust-size floor applies to non-base assets: [2](#0-1) .
3. Trigger the AA to pay out asset `X` (e.g., call its normal function that responds with an `X` payment).
4. In `sendUnit`/`completePaymentPayload`, `iterateUnspentOutputs` will greedily walk and include all attacker-planted dust `X` outputs as inputs because there is no per-message input cap for AA units: [4](#0-3) , [5](#0-4) .
5. Observe that the resulting AA-response unit contains a huge number of inputs, is exempt from `MAX_UNIT_LENGTH`, and that validating/writing this unit (and repeating for every future payout of asset `X` from this AA, since the dust keeps returning as change/re-sent) imposes disproportionate DB-query and processing cost on every full node during stabilization, compared to the trivial cost the attacker paid to create the dust outputs.

### Citations

**File:** aa_composer.js (L1102-1122)
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
```

**File:** aa_composer.js (L1144-1154)
```javascript
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
```

**File:** aa_composer.js (L1161-1173)
```javascript
				conn.query(
					"SELECT outputs.unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					CROSS JOIN unit_authors USING(unit) \n\
					CROSS JOIN aa_addresses ON unit_authors.address=aa_addresses.address \n\
					WHERE outputs.address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>="+FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND (main_chain_index>? OR main_chain_index IS NULL) \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY latest_included_mc_index, level, outputs.unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```

**File:** validation.js (L267-268)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```

**File:** validation.js (L2137-2138)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
```
