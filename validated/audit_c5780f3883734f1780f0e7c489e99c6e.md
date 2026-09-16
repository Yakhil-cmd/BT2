### Title
Unbounded input selection for AA response payment messages bypasses `MAX_INPUTS_PER_PAYMENT_MESSAGE`, enabling dust-flood DoS - (File: `aa_composer.js`, `validation.js`)

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` explicitly skips the `MAX_INPUTS_PER_PAYMENT_MESSAGE` anti-spam check for AA-generated units (`objValidationState.bAA`), while the AA response builder in `aa_composer.js` (`completePaymentPayload`/`iterateUnspentOutputs`) selects **all** unspent outputs belonging to the AA address with **no `LIMIT` clause** and no cap on the number of inputs it adds to a payment message. Any unprivileged sender can flood an AA address with a large number of tiny (but not dust-filtered) outputs over time; once the AA subsequently needs to spend/consolidate its balance (e.g. a "send all" response), the composer will pull in an unbounded number of inputs into a single message, producing an oversized unit that every node must revalidate.

### Finding Description
The per-message input cap is defined as: [1](#0-0) 

It is enforced in normal validation, but explicitly bypassed for AA units: [2](#0-1) 

The AA response composer that builds payment messages for AA responses (`completePaymentPayload`) pulls unspent outputs with no numeric limit: [3](#0-2) [4](#0-3) 

Contrast this with the equivalent wallet-side coin-selection routine (`inputs.js`), which explicitly caps the query at `MAX_INPUTS_PER_PAYMENT_MESSAGE-2`: [5](#0-4) 

The `aa_composer.js` code even acknowledges a dust-flood threat, but only mitigates it for the base asset and only by filtering the minimum size of a single output — not by bounding the *count* of inputs selected: [6](#0-5) 

For any non-base asset (i.e. a custom asset, including one the attacker itself defines and sends to the AA), there is no minimum-amount dust filter at all in `readStableOutputs`/`readUnstableOutputsSentByAAs`, so an attacker can trivially create thousands of tiny outputs to the AA address in ordinary payment units (any unprivileged unit poster can send payments to any address, including an AA address). Additionally, the general "unit too large" guard is also disabled for AA units after `pemCurvesFixMci`: [7](#0-6) [8](#0-7) 

So there is no size ceiling left to stop the AA response unit from growing arbitrarily large once the composer accumulates thousands of inputs.

### Impact Explanation
Once an attacker has flooded the AA's balance with a large number of small outputs, any trigger that causes the AA to spend its full/partial balance (a very common and legitimate pattern, e.g. `send_all` responses used throughout the test suite) forces `completePaymentPayload` to enumerate and include every one of those outputs as inputs in a single payment message, with no `MAX_INPUTS_PER_PAYMENT_MESSAGE` cap (bypassed for AAs) and no `MAX_UNIT_LENGTH` cap (bypassed for AAs post-`pemCurvesFixMci`). The resulting unit:
- Must be validated by every node, each of which loops over every input (e.g. `checkInputDoubleSpend`, `writer.js`'s per-input processing) doing a DB query per input — a heavy, unbounded per-unit workload.
- May become so large or slow to produce/validate that the AA can never successfully post a response (its own byte balance can also be drained by fees proportional to input count), effectively freezing the AA and preventing it from confirming further legitimate operations — an availability failure of the AA and additional processing load pushed onto the whole network for that unit.

This mirrors the reported Sherlock bug class: a per-operation limit (`MAXIMUM_NUMBER_OF_DEPOSITS_PER_ROUND` / `MAX_INPUTS_PER_PAYMENT_MESSAGE`) that is enforced on the "normal" path but silently bypassed on an alternate path (`depositETHIntoMultipleRounds` / AA-generated payment messages), letting an unprivileged actor inflate an internally-iterated collection without bound and eventually causing out-of-gas/DoS-style failure when that collection is processed (`fulfillRandomWords` / AA response building & network-wide unit validation).

### Likelihood Explanation
Likelihood is high: sending many small payments to a known AA address is a normal, unprivileged, low-cost operation (only bytes fees apply), and many AAs implement "send-all" style responses (as shown in the test fixtures) that are reachable by any user simply by triggering the AA with a qualifying payment.

### Recommendation
- Apply the same `MAX_INPUTS_PER_PAYMENT_MESSAGE` (or an AA-specific equivalent) limit to AA-generated payment messages in `validatePaymentInputsAndOutputs`, removing the `!objValidationState.bAA` bypass, or cap it explicitly.
- Add a `LIMIT` to the `readStableOutputs`/`readUnstableOutputsSentByAAs` queries in `aa_composer.js`, mirroring `inputs.js`'s `MAX_INPUTS_PER_PAYMENT_MESSAGE-2` cap, and handle overflow by bouncing/splitting across multiple response units instead of consuming unbounded rows.
- Extend the dust-amount filter (`FULL_TRANSFER_INPUT_SIZE` minimum) to non-base assets as well, or otherwise bound the total number of spendable outputs an AA will accumulate for a single asset.

### Proof of Concept
1. Attacker repeatedly sends ordinary payment units to a target AA address, each carrying a small (but not dust-filtered) output of a custom asset (or of bytes at/above `FULL_TRANSFER_INPUT_SIZE`), accumulating thousands of unspent outputs at the AA address over time — each individual unit passes normal validation since `MAX_OUTPUTS_PER_PAYMENT_MESSAGE`/`MAX_INPUTS_PER_PAYMENT_MESSAGE` apply per-unit, not cumulatively.
2. A legitimate user triggers the AA in a way that causes it to respond with a "send all" (or full-balance) payment for that asset, per the pattern in [9](#0-8) .
3. `completePaymentPayload`/`iterateUnspentOutputs` in `aa_composer.js` selects every accumulated output with no `LIMIT`, producing a payment message whose `inputs.length` vastly exceeds `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` (128).
4. `validatePaymentInputsAndOutputs` in `validation.js` does not reject this because the `MAX_INPUTS_PER_PAYMENT_MESSAGE` check is skipped for `objValidationState.bAA`, and the overall unit-size check is likewise skipped for AA units, allowing the oversized unit through and forcing costly re-validation by every receiving node.

### Citations

**File:** constants.js (L47-47)
```javascript
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
```

**File:** validation.js (L267-268)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```

**File:** validation.js (L744-745)
```javascript
					if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && objValidationState.bAA && objValidationState.last_ball_mci < constants.pemCurvesFixMci)
						return callback("unit too large");
```

**File:** validation.js (L2137-2140)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
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

**File:** aa_composer.js (L1140-1173)
```javascript
			function readStableOutputs(handleRows) {
			//	console.log('--- readStableOutputs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
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
			}

			function readUnstableOutputsSentByAAs(handleRows) {
			//	console.log('--- readUnstableOutputsSentByAAs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
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

**File:** inputs.js (L130-145)
```javascript
		conn.query(
			`SELECT unit, message_index, output_index, amount, address, blinding
			FROM outputs
			CROSS JOIN units USING(unit)
			${conf.bLight ? "LEFT JOIN aa_responses ON unit=response_unit" : ""}
			WHERE address IN(?) AND asset${asset ? "="+conn.escape(asset) : " IS NULL"} AND is_spent=0
				AND sequence='good' ${confirmation_condition}
				${constants.bDevnet
					? ""
					: (conf.bLight
						? `AND ( response_unit IS NULL OR aa_responses.creation_date<${conn.addTime('-30 SECOND')} )`
						: `AND ( units.is_aa_response IS NULL OR units.creation_date<${conn.addTime('-30 SECOND')} )`
					)
				}
			ORDER BY amount DESC LIMIT ?`,
			[arrSpendableAddresses, constants.MAX_INPUTS_PER_PAYMENT_MESSAGE-2],
```

**File:** test/samples/send_all.oscript (L1-30)
```text
{
	messages: {
		cases: [
			{
				if: `{trigger.output[[asset=base]] >= 1e6}`,
				messages: [{
					app: 'payment',
					payload: {
						asset: 'base',
						outputs: [
							{ address: '{trigger.address}' }
						]
					}
				}]
			},
			{
				messages: [{
					app: 'payment',
					payload: {
						asset: 'base',
						outputs: [
							{ address: 'X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', amount: `{round(trigger.output[[asset=base]]/2)}` },
							{ address: '{trigger.address}' }, // no amount here meaning that this output receives all the remaining coins
						]
					}
				}]
			},
		]
	}
}
```
