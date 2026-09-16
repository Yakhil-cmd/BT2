### Title
Missing dust-threshold on non-base assets lets any user force AAs to accumulate unbounded tiny inputs when composing custom-asset payments - ([File: aa_composer.js])

### Summary
When an AA composes an outgoing payment, `completePaymentPayload`'s `readStableOutputs`/`readUnstableOutputsSentByAAs` helpers only apply the anti-dust minimum `FULL_TRANSFER_INPUT_SIZE` (60 bytes) filter to base-asset (bytes) outputs. For any other, freely issuable custom asset, the `WHERE` clause is simply `asset=?` with no lower bound on `amount`, so every unspent output of that asset at the AA's address — however tiny — is eligible to be pulled in as an input.

### Finding Description
The dust-attack mitigation comment is explicit about the intent: [1](#0-0) 

but the SQL only enforces `amount>=FULL_TRANSFER_INPUT_SIZE` in the branch where `asset` is falsy (i.e., base/bytes):
```
WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0
```
The same asymmetry exists in `readUnstableOutputsSentByAAs`: [2](#0-1) 

`iterateUnspentOutputs` then walks every returned row and unconditionally pushes it as an input until the target amount is reached: [3](#0-2) 

Custom assets in ocore are permissionless: any unit poster can issue an asset (via an `asset` definition message, validated in `validateAssetDefinition`) and freely choose `denominations`/`cap` and send arbitrarily many outputs of arbitrarily small amounts to any address, including an AA address. [4](#0-3) 

Because payment inputs are also exempted from the general input-count cap when the author is an AA (`!objValidationState.bAA` guards the check), the AA's own generated response unit is not itself capped there either — the cap only guards units authored by the attacker, not the number of inputs an AA can accumulate while composing its response: [5](#0-4) 

This is the direct analog of the reported issue: a protocol-level anti-spam threshold (`offerBorrowAmountLowerBound` in the external report / `FULL_TRANSFER_INPUT_SIZE` dust filter here) is applied inconsistently across "token" classes — enforced for one asset class (bytes) but not for the other (arbitrary custom assets), even though the underlying attack vector (spamming tiny value units to force expensive future processing by a victim) is identical, and — unlike the ERC20 case where governance could in theory set a per-token bound — ocore has no equivalent per-asset configurable threshold or allow-list at all for AA-received asset outputs.

### Impact Explanation
An attacker can issue a custom asset for a negligible cost and repeatedly send outputs of amount 1 (or the smallest denomination) of that asset to a target AA's address. Any time that AA is triggered and needs to pay out in that asset (e.g., a DEX/exchange AA, a token-wrapping AA, or any AA that forwards or returns a custom asset), `completePaymentPayload` will greedily consume every one of these dust outputs as payment inputs before it can satisfy the target amount, because there is no lower bound filtering them out. This:
- inflates the size (and hence fees) of AA-generated response units, potentially exceeding the oversize-fee budget or unit size limits and causing bounces that permanently waste the AA's balance on fees without completing legitimate business logic;
- can be used to grief/freeze AA funds denominated in that asset, since the AA can no longer efficiently or successfully compose payments in it;
- degrades node performance servicing that AA (large SQL result sets, large unit composition), a spam/DoS vector reachable by a single unprivileged unit poster with no special privileges.

This matches "AA fund loss or freezing" and "network unable to confirm new units" (from that AA) categories.

### Likelihood Explanation
High likelihood: issuing a custom asset and sending many tiny-amount outputs to a known AA address requires only ordinary unit-posting capability (no elevated privilege), is cheap (dust amounts, only bytes-denominated posting fees are paid by the attacker), and is fully deterministic — any AA that pays out balances in a non-base asset it receives from third parties is exposed.

### Recommendation
Apply an equivalent dust-amount lower bound (or a per-asset configurable minimum, mirroring `FULL_TRANSFER_INPUT_SIZE`'s intent) to the non-base branch of the `readStableOutputs` / `readUnstableOutputsSentByAAs` queries in `aa_composer.js`, e.g. requiring `amount` to exceed the marginal storage/processing cost of adding that input, or capping the number of custom-asset inputs an AA will accumulate per payload (similar in spirit to `MAX_INPUTS_PER_PAYMENT_MESSAGE`, but actually enforced for AA-authored units as well).

### Proof of Concept
1. Attacker issues asset `X` with `is_transferrable: true`, `issued_by_definer_only: false`, no cap — a completely standard custom asset definition validated by `validateAssetDefinition` (`validation.js:2725`).
2. Attacker crafts thousands of units, each with a single payment message in asset `X` sending amount `1` to a target AA address `A` that is known to periodically send out asset `X` (e.g., an exchange/order-book AA as in `test/samples/order_book_exchange.oscript`).
3. Once triggered to make a payment in asset `X` to some recipient, the AA's `completePaymentPayload` runs `readStableOutputs` with `WHERE address=A AND asset='X' AND is_spent=0 ...` (no amount filter), returning all of the attacker's dust outputs.
4. `iterateUnspentOutputs` adds them all as `payload.inputs`, one 44+8+8-byte input per 1-unit dust output, producing an oversized unit whose fees vastly exceed the value being moved, causing the response either to fail composition, bounce, or drain the AA's byte balance on fees.

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

**File:** validation.js (L2137-2140)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
```

**File:** validation.js (L2725-2733)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");
```
