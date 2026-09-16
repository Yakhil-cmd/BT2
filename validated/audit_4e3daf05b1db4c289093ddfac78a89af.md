### Title
Dust-output flooding of a custom asset lets an attacker force an AA into an unbounded/oversized input set when composing responses, freezing the AA's asset funds - (File: aa_composer.js, validation.js)

### Summary
`aa_composer.js`'s payment-composition logic filters out dust (sub-`FULL_TRANSFER_INPUT_SIZE`) unspent outputs only for the base asset, not for custom assets, and the resulting AA-generated payment message is explicitly exempted from the `MAX_INPUTS_PER_PAYMENT_MESSAGE` anti-spam limit in `validation.js`. An attacker can flood an AA address with a large number of dust-amount custom-asset outputs, forcing any future AA response that must pay out that asset to accumulate an unbounded number of inputs, analogous to the reported `getLockedFunds`/`deposits`-iteration DoS.

### Finding Description
When an AA composes an outgoing payment for an asset, it selects unspent outputs via `readStableOutputs`/`readUnstableOutputsSentByAAs` and iterates over every returned row in `iterateUnspentOutputs` until the target amount is reached: [1](#0-0) 

The queries backing this selection contain a dust-amount filter, but it only applies to the base (bytes) asset — for a custom asset there is no minimum-amount condition at all: [2](#0-1) [3](#0-2) 

The comment on line 1144 explicitly acknowledges the dust-spamming risk ("spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond") but the protection (`amount>=FULL_TRANSFER_INPUT_SIZE`) is wired only into the `IS NULL` (base-asset) branch of the SQL, not into the `asset=?` branch.

Any unprivileged user can trivially and cheaply send many payment units, each transferring a tiny (e.g. 1-unit) amount of a custom asset to the AA's address — a normal, permission-less "payment" message, exactly like the report's attacker calling `fundBountyToken` repeatedly with minimal amounts. This populates the `outputs` table with an unbounded number of unspent, un-filterable dust outputs of that asset at the AA address.

Normally, an oversized `payload.inputs` array would be rejected by the anti-spam check in `validatePaymentInputsAndOutputs`: [4](#0-3) 
but this check is explicitly bypassed when the payment is AA-generated (`!objValidationState.bAA`). So the very code path meant to protect the network from huge input lists does not protect AA-issued responses, and there is no equivalent cap enforced inside `aa_composer.js`'s output-selection loop itself (no `LIMIT` on the SQL query, no cap on iterations in `iterateUnspentOutputs`).

### Impact Explanation
Once enough dust outputs of the targeted asset exist at the AA's address, any legitimate trigger that causes the AA to send/forward/refund that asset will force `completePaymentPayload` to walk through and consume a very large number of these outputs as payment inputs. Consequences:
- The composed payment message/unit can grow far beyond normal size, risking `MAX_UNIT_LENGTH` rejection or extremely slow unit composition/validation on every node that re-validates it, i.e. the same "an operation that iterates over an attacker-controlled, unbounded collection blocks a critical fund-moving path" failure mode as the reported `getLockedFunds`/refund DoS.
- Because the AA's response composition can never finish successfully (or is prohibitively slow/oversized), the AA becomes unable to pay out that asset, effectively freezing user funds held by the AA in that asset — a concrete AA fund-freezing condition.
- Since `MAX_INPUTS_PER_PAYMENT_MESSAGE` is bypassed for AA units, there is no consensus-level backstop that would otherwise cap the damage.

### Likelihood Explanation
The precondition (an AA that holds and is expected to pay back a custom, non-base asset — e.g., an escrow, DEX, or bridge AA) is common in Autonomous Agent design patterns. Creating the dust outputs requires only ordinary, unprivileged "payment" messages transferring the asset in tiny amounts to the AA address, which is inexpensive for the attacker if they control (or can cheaply acquire units of) the target asset, mirroring the original report's note that deposit-flooding is far more attractive on low-fee networks. No special privilege, timing, or race condition is needed — an attacker just needs to send enough small transfers before the AA needs to make a large asset payout.

### Recommendation
Apply the same dust-avoidance principle used for the base asset to custom assets in `aa_composer.js`'s `readStableOutputs`/`readUnstableOutputsSentByAAs` queries, e.g., enforce a minimum-amount threshold (or minimum value relative to fees) for asset outputs as well, and/or impose an explicit cap (with `LIMIT`) on the number of outputs/inputs an AA response composition will consume, independent of the `objValidationState.bAA` exemption in `validation.js`. Consider also enforcing (or lowering) `MAX_INPUTS_PER_PAYMENT_MESSAGE` for AA-generated messages, or requiring AAs to explicitly opt into "sweep all dust" behavior rather than making the default output-selection algorithm inherently unbounded for custom assets.

### Proof of Concept
1. Deploy or use an existing AA that is designed to receive and pay back a custom (non-base) asset (e.g. an escrow/bridge/exchange AA).
2. As an unprivileged attacker who possesses (or can issue/acquire) small amounts of that asset, repeatedly post ordinary payment units transferring 1 unit of the asset to the AA's address — no special permission needed, this is standard asset transfer functionality validated by `validatePaymentInputsAndOutputs`.
3. Repeat until the AA holds a very large number of dust unspent outputs for that asset (bounded only by the attacker's patience/cost, since `readStableOutputs`'s custom-asset branch applies no minimum-amount filter, unlike the base-asset branch at [5](#0-4) ).
4. Trigger the AA's normal logic that causes it to send back/forward that asset (e.g., a refund or payout trigger).
5. Observe that `completePaymentPayload`/`iterateUnspentOutputs` at [1](#0-0)  is forced to enumerate and include a very large number of the attacker-created dust inputs, producing an oversized/slow-to-process payment message that `validatePaymentInputsAndOutputs` does not reject on input count due to the `!objValidationState.bAA` exemption at [6](#0-5) , preventing the AA from completing the asset payout.

### Citations

**File:** aa_composer.js (L1102-1123)
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
```

**File:** aa_composer.js (L1144-1155)
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

**File:** validation.js (L2136-2138)
```javascript
	var total_input = 0;
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
```
