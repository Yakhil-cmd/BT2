Found a concrete analog: in `aa_composer.js`, when an AA needs to compose an outgoing payment (`sendUnit` → `completePaymentPayload`), the code reads **all** unspent outputs of the AA's address for the given asset via `readStableOutputs`/`readUnstableOutputsSentByAAs` (no `LIMIT` clause) and then iterates over every row in `iterateUnspentOutputs` to accumulate inputs until the target amount is reached. The comment at [1](#0-0)  even acknowledges the dust-attack class of problem ("byte outputs less than 60 bytes ... spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond"), but the mitigation only filters out sub-`FULL_TRANSFER_INPUT_SIZE` byte outputs — it does not cap the *number* of qualifying outputs that can accumulate on an AA's address, nor bound the loop that walks them.

### Title
Unbounded iteration over AA unspent outputs in payment composition can freeze AA fund transfers - (aa_composer.js)

### Summary
`completePaymentPayload`'s `iterateUnspentOutputs` loops over every row returned by `readStableOutputs`/`readUnstableOutputsSentByAAs`, which select **all** unspent, non-dust outputs at an AA's address with no `LIMIT`, unlike the equivalent user-wallet coin-selection routine `pickDivisibleCoinsForAmount` in `inputs.js`, which explicitly caps the candidate set with `LIMIT ?` bound by `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE-2` [2](#0-1) .

### Finding Description
Any unprivileged unit poster can send many small (just above the dust floor `FULL_TRANSFER_INPUT_SIZE`) payments to an AA address across many units. Each such payment becomes a distinct unspent output row at the AA's address. When the AA later needs to send a payment (triggered by any user's AA trigger), `sendUnit`/`completePaymentPayload` queries all unspent outputs for the relevant asset with no cap: [3](#0-2)  and [4](#0-3) , then walks the full result set inside `iterateUnspentOutputs`, pushing one input per row and recomputing `net_target_amount`/`size`/`target_amount` for each: [5](#0-4) . Because every additional input increases `size` (and, above `aaStorageSizeUpgradeMci`, the oversize fee), an attacker who fragments the AA's balance into thousands of minimal (dust-floor) outputs can force this loop to run over an unbounded number of iterations for every single AA trigger that causes the AA to pay out in that asset — this is directly analogous to the reported `_getUnlockedLiquidity` unbounded loop over `lockedAmounts`, where an attacker inflates the array the victim must fully traverse before functionality unlocks.

### Impact Explanation
If the number of dust-floor outputs at the AA's address is large enough, `completePaymentPayload`'s synchronous-style loop (`for (var i = 0; i < rows.length; i++)`) must process the entire array before the trigger's response unit can be composed. Practically, this degrades to node stalls/response construction failures for every trigger that requires the AA to make a base-asset (or asset) payment from that flooded balance, effectively freezing legitimate fund transfers out of the AA (a griefing/DoS on AA funds availability) until the outputs are somehow consolidated — which itself requires the AA to pay them out, i.e., go through the same unbounded loop. This matches the accepted impact class "AA fund loss or freezing."

### Likelihood Explanation
Likelihood is low-to-medium: it requires the attacker to send many separate small payments to the target AA address (each above the existing dust floor of `FULL_TRANSFER_INPUT_SIZE`), incurring the attacker's own transaction/fee costs per output created. However, this is fully permissionless — any address can pay any AA — and cheap relative to the potential to indefinitely degrade a high-value AA's ability to disburse funds, especially for AAs that receive frequent public deposits (e.g., DEX/pool-style AAs).

### Recommendation
Apply the same bound already used in `inputs.js`'s `pickDivisibleCoinsForAmount`: add a `LIMIT` (e.g., `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE`) to the `readStableOutputs`/`readUnstableOutputsSentByAAs` queries in `aa_composer.js`, and if the accumulated amount from the limited set is insufficient, fail gracefully (bounce) rather than attempt to read/iterate an unbounded number of outputs. Consider also raising the dust floor or introducing a periodic/explicit consolidation mechanism bounded per invocation so an AA can gradually merge dust outputs without a single unbounded pass.

### Proof of Concept
1. Deploy or use an existing AA `A` that pays out its balance (or part of it) to users in response to triggers.
2. From attacker-controlled addresses, send `N` (e.g., 5,000–50,000) separate payment units to `A`, each carrying a byte output amount just above `FULL_TRANSFER_INPUT_SIZE` (the existing anti-dust floor referenced at [1](#0-0) ), until `A` accumulates `N` unspent outputs.
3. Trigger `A` with a legitimate unit that causes it to send a base-asset payment (`sendUnit`).
4. Observe that `completePaymentPayload`'s `readStableOutputs` query returns all `N` rows unbounded [3](#0-2) , and `iterateUnspentOutputs` must loop through them [5](#0-4) , causing response composition time/cost to grow linearly (unbounded) with `N`, unlike wallet-initiated payments which are capped via `LIMIT` in `inputs.js`.

### Citations

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

**File:** aa_composer.js (L1144-1144)
```javascript
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
```

**File:** aa_composer.js (L1145-1154)
```javascript
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
