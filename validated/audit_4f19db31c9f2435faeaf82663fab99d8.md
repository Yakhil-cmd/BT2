### Title
Unbounded consumption of unspent asset outputs when an AA composes a payment response allows dust-output DoS causing AA fund freezing - (File: aa_composer.js)

### Summary
`sendUnit()`'s inner `completePaymentPayload()` in `aa_composer.js` selects every unspent output of a non-base asset held by the AA address with no minimum-amount filter and no cap on the number of inputs consumed, unlike the base-asset case (which enforces `amount>=FULL_TRANSFER_INPUT_SIZE`) and unlike `indivisible_asset.js`'s coin-picking, which explicitly caps `arrPayloadsWithProofs.length` against `constants.MAX_MESSAGES_PER_UNIT - 1`. Any unprivileged unit poster who controls units of a custom asset can permissionlessly flood an AA's address with a very large number of dust-amount outputs of that asset, causing a later legitimate AA payment response in that asset to accumulate an unbounded number of inputs and fail unit-size/message-count validation, effectively freezing the AA's use of its own asset balance.

### Finding Description
In `completePaymentPayload()`, `readStableOutputs()` and `readUnstableOutputsSentByAAs()` build a SQL query to select all unspent outputs of the asset being spent: [1](#0-0) 

Note the amount filter is conditional on asset: `asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+"` — for a non-base custom asset (`asset` truthy), there is **no minimum amount requirement at all**, and there is also **no `LIMIT`** on the query. The comment above even documents the anti-dust rationale but only for bytes: [2](#0-1) 

The returned rows are then consumed one by one in `iterateUnspentOutputs()`: [3](#0-2) 

This loop keeps pushing an `input` for every row into `payload.inputs` until `total_amount` reaches `target_amount`, with **no cap on the number of inputs added** for the asset case (the `is_base` branch adjusts size/fees, but nothing bounds the number of asset inputs). Compare this to the indivisible-asset coin-picker which explicitly guards against this: [4](#0-3) 

No equivalent guard exists in `aa_composer.js`'s divisible-asset accumulation path.

Any unprivileged holder/issuer of the custom asset can send the AA address a very large number of tiny-amount (e.g., amount=1) payment outputs of that asset across multiple units (each such payment is a normal, valid payment message the attacker composes and pays bytes fee for once). Because there is no per-output minimum and no query `LIMIT`, once the AA subsequently needs to send out even a small amount of that asset (a common pattern in AA logic, e.g., forwarding or returning asset balances to `trigger.address`), `completePaymentPayload` will attempt to consume all (or a huge portion) of these dust outputs to satisfy the target amount, producing a unit with an oversized `payload.inputs` array.

### Impact Explanation
Such an oversized response unit will fail unit-size/message-count constraints during normal unit assembly and validation, e.g., the "unit too large" checks enforced in `validation.js`: [5](#0-4) 

Since `sendUnit()`'s `completePaymentPayload` callback path (`cb(err)`) propagates any error to `bounce()`, the AA response will keep bouncing whenever it must send that particular asset, since the same dust-laden output set will be re-selected on every subsequent trigger. This permanently locks/freezes the AA's balance in that asset — a concrete "AA fund loss or freezing" outcome, reachable purely by a single unprivileged asset holder/issuer repeatedly sending small payments to the AA address, without needing any special privileges, matching the impact class validated by the rules.

### Likelihood Explanation
The attack requires no privileged role: any address holding units of the target custom asset (including the asset's own issuer, or an attacker who self-issues a fresh asset the AA is designed to interact with) can send arbitrarily many dust-amount payment outputs to the target AA, paying only the ordinary byte fees for the base-asset unit shells. This is directly analogous to the referenced Union Finance bug where an unprivileged actor griefs another party's array by repeatedly appending near-zero-value entries that are later iterated without bound.

### Recommendation
- Apply a minimum spendable-amount filter to non-base assets in `readStableOutputs`/`readUnstableOutputsSentByAAs` similar to the base-asset `amount>=FULL_TRANSFER_INPUT_SIZE` filter (or an asset-aware equivalent), and/or add a `LIMIT` to the SQL queries.
- In `iterateUnspentOutputs`, cap the number of inputs consumed against `constants.MAX_MESSAGES_PER_UNIT` (mirroring the existing guard in `indivisible_asset.js`), stopping accumulation and issuing a clear bounce error rather than silently building an oversized unit that will always fail validation.
- Consider prioritizing larger-amount outputs first (as `pickDivisibleCoinsForAmount` in `inputs.js` does) to minimize the number of inputs needed to satisfy `target_amount`, reducing susceptibility to dust flooding.

### Proof of Concept
1. Attacker issues (or already holds) a custom asset `A` that the target AA `X` is programmed to accept/forward (e.g., `X` responds to triggers carrying asset `A` by paying part of it back to `trigger.address`).
2. Attacker composes many payment units, each sending output(s) of asset `A` to address `X` with `amount = 1` (or any dust value), repeated until thousands of unspent outputs of asset `A` accumulate at `X`'s address — nothing in validation prevents this since there is no per-asset dust threshold.
3. Attacker (or any user) then sends a normal trigger to `X` that causes `X`'s bytecode to attempt sending out any positive amount of asset `A`.
4. `completePaymentPayload` calls `readStableOutputs`, which returns all (thousands of) unspent dust outputs of asset `A` with no `LIMIT`; `iterateUnspentOutputs` pushes an input for every row without a cap, producing `payload.inputs` far beyond `constants.MAX_MESSAGES_PER_UNIT`.
5. The resulting oversized unit fails `validation.js` size/message checks, so `sendUnit` reports the error to `bounce()`, and this happens on every subsequent trigger requiring `X` to spend asset `A`, permanently freezing `X`'s use of that asset balance.

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

**File:** indivisible_asset.js (L503-504)
```javascript
					if (arrPayloadsWithProofs.length >= constants.MAX_MESSAGES_PER_UNIT - 1) // reserve 1 for fees
						return onDone("Too many messages, try sending a smaller amount");
```

**File:** validation.js (L267-268)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```
