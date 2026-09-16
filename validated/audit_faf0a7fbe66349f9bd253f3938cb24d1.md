### Title
Unbounded dust-output accumulation in AA response payments for non-base assets bypasses input-count anti-spam limit and can DoS an AA's ability to respond - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s coin-picking logic for AA-generated payment responses (`readStableOutputs`/`readUnstableOutputsSentByAAs`/`iterateUnspentOutputs`) only filters out dust outputs for the base asset (`amount >= FULL_TRANSFER_INPUT_SIZE`), leaving custom-asset outputs completely unfiltered and unbounded in count. Combined with the fact that `validation.js`'s `MAX_INPUTS_PER_PAYMENT_MESSAGE` check is explicitly skipped for AA-generated units, an attacker can flood an AA address with thousands of near-zero-value custom-asset outputs at negligible cost, then trigger the AA to spend/forward that asset. The AA's response-composition logic will attempt to consume all these dust inputs into a single payment message, unboundedly, producing an oversized/slow-to-build unit and potentially rendering the AA unable to produce a valid response — an on-chain analog of the reported `deposit`/`requestWithdraw` unbounded-request DoS.

### Finding Description
In `aa_composer.js`, when an AA response needs to pay out a given asset, `completePaymentPayload` calls `readStableOutputs` and `readUnstableOutputsSentByAAs` to find spendable outputs owned by the AA: [1](#0-0) [2](#0-1) 

The comment on line 1144 explicitly documents the known dust-attack mitigation for the **base** asset: outputs smaller than `FULL_TRANSFER_INPUT_SIZE` (~60 bytes worth of fee) are excluded because they would be net-negative to spend and could be used to spam an AA into paying fees for garbage inputs. Critically, this filter (`amount>=FULL_TRANSFER_INPUT_SIZE`) is applied **only when `asset` is falsy** (i.e., only for the base currency). For any custom/non-base asset, the `WHERE` clause reduces to `asset=?` with no minimum-amount condition, so an attacker can create arbitrarily many outputs of size 1 (or any tiny amount) of a given asset sent to the AA address, and every single one of them will be returned by these queries.

`iterateUnspentOutputs`, which consumes these rows, loops through **all** rows returned with no cap on the number of inputs pushed into `payload.inputs`: [3](#0-2) 

Compare this to the wallet-side coin picker in `inputs.js`, which explicitly caps the number of picked inputs at `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE-2`: [4](#0-3) 

No equivalent cap exists in the AA composer's coin-picking loop for non-base assets.

Finally, `validation.js`'s general anti-spam check for payment message input count is explicitly bypassed for AA-generated units: [5](#0-4) 
`payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA` — the `!objValidationState.bAA` guard means AA response units are not subject to the 128-input cap that ordinary wallet payments are subject to.

Taken together: (1) dust filtering for AA coin-picking exists only for base bytes, not custom assets; (2) the AA's own coin-picking has no input-count limit; (3) even if it did produce a huge input list, unit validation would not reject it for having "too many inputs" because that check is skipped for AAs. The only remaining backstop is `constants.MAX_UNIT_LENGTH` (5MB) and general unit-size/oversize-fee mechanics, but by then the AA has already spent significant time/resources building (and possibly the network validating) an enormous unit, and if the resulting fee/size math causes the payment to fail to complete, the AA response bounces or errors out — while the underlying dust outputs remain unconsumed and can be re-fed indefinitely at near-zero cost by the attacker (mirroring the reported `deposit`/`requestWithdraw` DOS pattern: unlimited actions with no minimum-amount floor).

### Impact Explanation
Any AA that accepts an arbitrary custom asset for deposit and later needs to aggregate/spend its full balance of that asset in a single payment message (a common pattern, e.g. vault/pool-style AAs, similar in spirit to `SolverVault.deposit`) can be bricked by an attacker sending large numbers of dust-sized outputs of that asset to the AA's address. Once enough dust outputs accumulate:
- The AA's response-building logic in `aa_composer.js` attempts to include all of them as inputs, producing units whose composition cost (query time, JSON size, hashing, size/fee computation) grows unbounded with the number of dust outputs, and/or a unit that becomes too large to be valid (`MAX_UNIT_LENGTH`) or economically infeasible (fees consume the whole payout).
- This can freeze the AA's legitimate accumulated asset balance (funds effectively unspendable in one op) and/or cause repeated trigger failures/bounces for all subsequent users interacting with that asset-holding AA, which is a fund-freezing / node-inability-to-process-the-AA condition — reachable purely by an unprivileged user issuing ordinary payment messages (posted units) to the AA, at negligible per-output cost.

### Likelihood Explanation
Likelihood is moderate-to-high for any AA design that (a) accepts a custom asset from arbitrary triggering addresses and (b) later needs to aggregate/send out its full balance of that asset in one payment (send-all or accumulated-balance payout, a common and encouraged AA pattern). The attack requires only ordinary payment units with many small outputs to the target AA address — well within reach of any single account, and cheap because payment message outputs are only bounded by `MAX_OUTPUTS_PER_PAYMENT_MESSAGE` (128) per unit but an attacker can post many units over time to accumulate thousands of dust outputs. No special privileges, AA-authoring rights, or network position are required — only whether a target AA's oscript accumulates/pays out a custom asset it does not control mint conditions for.

### Recommendation
- Apply the same dust-filtering principle used for the base asset to custom assets in `readStableOutputs`/`readUnstableOutputsSentByAAs` in `aa_composer.js` — e.g., require `amount` to exceed some minimum bytes-equivalent threshold (accounting for the marginal cost of including the input in the response unit), or make the threshold asset-aware/configurable.
- Enforce a hard cap on the number of inputs `iterateUnspentOutputs` will accumulate for a single AA payment message, consistent with `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE`, mirroring the cap already present in `inputs.js`'s `pickMultipleCoinsAndContinue`.
- Reconsider exempting AA-generated units from the `too many inputs` check in `validation.js` (`!objValidationState.bAA`), or replace the blanket exemption with a still-bounded, AA-appropriate limit, so a maliciously-inflated dust set cannot produce arbitrarily large payment messages even if it slips past AA-composer-side limits.

### Proof of Concept
1. Deploy (or target) an AA that accepts a custom asset `X` as deposits from arbitrary addresses and later, on some trigger, pays out its accumulated `X` balance to a recipient (a `send-all` style payment in asset `X`), similar to a vault/pool AA.
2. As an attacker, repeatedly post ordinary payment units transferring output amounts of `1` unit of asset `X` to the AA's address — each unit can carry up to `MAX_OUTPUTS_PER_PAYMENT_MESSAGE` (128) dust outputs; repeat across many units to accumulate thousands of unspent dust outputs of asset `X` owned by the AA (`outputs` table rows), at negligible cost since there is no minimum-amount floor for non-base assets as there is for the base asset (see `aa_composer.js:1149`,`1167`).
3. Trigger the AA's payout logic for asset `X`. In `completePaymentPayload`/`iterateUnspentOutputs` (`aa_composer.js:1102-1138`), the coin-picker will pull in all of the attacker's dust outputs (no per-asset minimum, no cap on count), producing a payment message with a very large number of inputs.
4. Because `validation.js:2137-2140` exempts AA-generated units (`!objValidationState.bAA`) from the `MAX_INPUTS_PER_PAYMENT_MESSAGE` cap, this oversized input list is not rejected by that specific check, but the resulting unit's overall size/fee economics (and potentially `MAX_UNIT_LENGTH`) can make composing a valid response unit fail or extremely expensive, causing the AA to bounce/fail on subsequent invocations that need to touch its `X` balance, effectively freezing those funds and disrupting the AA's normal operation for all users.

Note: I was not able to fully trace the exact failure mode (bounce vs. hard exception vs. successful-but-oversized unit) once the input count grows very large, since that depends on interplay between `objectLength.getTotalPayloadSize`, oversize-fee computation, and `MAX_UNIT_LENGTH` checks in `validation.js`, which I could not fully execute/trace in this review — a live PoC test (e.g., in `test/aa_composer.test.js`) would be needed to confirm the precise breaking point and resulting failure behavior. [6](#0-5) [7](#0-6)

### Citations

**File:** aa_composer.js (L1102-1138)
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
			}
```

**File:** aa_composer.js (L1140-1155)
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
```

**File:** aa_composer.js (L1157-1173)
```javascript
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

**File:** inputs.js (L128-145)
```javascript
	// then, try to add smaller coins until we accumulate the target amount
	function pickMultipleCoinsAndContinue(){
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

**File:** validation.js (L2137-2140)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
```

**File:** constants.js (L47-48)
```javascript
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_OUTPUTS_PER_PAYMENT_MESSAGE = 128;
```

**File:** constants.js (L59-59)
```javascript
exports.MAX_UNIT_LENGTH = process.env.MAX_UNIT_LENGTH || 5e6;
```
