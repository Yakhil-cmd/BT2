### Title
Unbounded dust-output accumulation lets an unprivileged sender DOS an AA's ability to spend a given asset - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `sendUnit()` builds outgoing payment payloads for an AA by querying **all** unspent outputs owned by the AA address for the asset being paid out (`readStableOutputs`/`readUnstableOutputsSentByAAs`) and then looping over every returned row in `iterateUnspentOutputs()` to add it as an input. For base (bytes) payments this query filters out outputs smaller than `FULL_TRANSFER_INPUT_SIZE` to avoid dust, but for non-base assets **no minimum-amount filter is applied at all**. [1](#0-0) [2](#0-1) 

### Finding Description
Any unprivileged user who can send a "payment" message of a given (non-base) asset to an AA address can create an arbitrarily large number of tiny/dust outputs owned by that AA in that asset, exactly as in the reported bug class where a malicious depositor inflates a per-address array (`deposits`) that a later state-changing function (`refundDeposit`) must iterate. Here the analogous "growing array" is the set of unspent `outputs` rows for `(address=AA, asset=X)`, which grows by 1 every time anyone sends the AA even 1 unit of asset X, with no lower bound and no cap on count.

When the AA subsequently needs to send a payment message in asset X (triggered by any legitimate future trigger, e.g. distributing funds, refunds, swaps, etc.), `completePaymentPayload()` calls:
- `readStableOutputs()` — `SELECT ... FROM outputs ... WHERE address=? AND asset=? AND is_spent=0 ...` with **no amount floor and no LIMIT** for the asset case [3](#0-2) 
- `iterateUnspentOutputs(rows)` — a JS `for` loop over every row returned, pushing each into `payload.inputs`/`arrConsumedOutputs` until the target amount is reached [2](#0-1) 

This is the direct on-chain analog of `BountyCore`'s `receiveFunds()`/`getLockedFunds()` pattern: an attacker cheaply grows a per-address collection with numerous negligible-value entries; a later necessary state-changing operation must load/iterate that collection in full, and the cost/likelihood of failure scales with the number of dust entries the attacker chooses to create. The explicit code comment at line 1144 (`"byte outputs less than 60 bytes... are ignored to prevent dust attack: spamming the AA..."`) confirms the ocore authors already recognized and mitigated this exact attack for the base-byte case, but the mitigation is missing for asset payments. [4](#0-3) 

Because `payload.inputs` accumulates one entry per dust output and a unit is bounded by `constants.MAX_MESSAGES_PER_UNIT` (and per-unit size/oversize-fee limits), an attacker who floods an AA address with enough zero/near-zero-value asset outputs can make it impossible for the AA to ever assemble a valid response unit for that asset: the input list either fails to reach the target amount using only the first outputs consumed (if `MAX_INPUTS`-style limits aren't hit first) or the resulting unit becomes oversized/invalid, causing the AA response to bounce every time it tries to pay out that asset. Even short of full failure, every legitimate trigger that causes the AA to spend that asset now pays the CPU/DB cost of scanning and processing the entire dust set, which grows without bound as long as the attacker keeps sending 1-unit outputs — mirroring the reported "cheap-attack-inflates-array, expensive-legitimate-operation-iterates-it" DOS pattern.

### Impact Explanation
If exploited, this permanently or repeatedly bounces legitimate AA operations that need to pay out the targeted asset (fund loss/freezing for AA users relying on that response, e.g., swap AAs, bonding curves, or any AA logic sending asset payments), and degrades node performance for every trigger touching that AA/asset pair. This matches the "AA fund loss or freezing" / "network unable to confirm new units" acceptance criteria, since the AA's outgoing unit for that asset can become unconstructible.

### Likelihood Explanation
Any user can send a payment message with an arbitrary asset amount (down to the asset's smallest denomination) to any AA address; this requires no special privilege, no whitelisting, and costs only the transfer fee/dust amount itself — directly analogous to the "1 wei / less than $50" cost noted in the original report. The attack is reachable purely by posting ordinary payment units to a public AA address, which is the standard unprivileged-poster path this scan targets.

### Recommendation
Apply the same dust-prevention filter used for base outputs to asset outputs in `readStableOutputs()`/`readUnstableOutputsSentByAAs()`: require `amount >= some_minimum` (e.g., proportional to `FULL_TRANSFER_INPUT_SIZE` or a per-asset minimum useful denomination) for asset outputs as well, and/or cap the number of rows fetched/processed per `completePaymentPayload()` call (e.g., add a `LIMIT`), consolidating any leftover dust into future queries instead of loading the entire unbounded set at once.

### Proof of Concept
1. Attacker repeatedly sends `payment` units to AA address `A`, each with a single output of asset `X` and amount `1` (or any value smaller than a reasonable dust threshold), to `A`. Nothing prevents this since `readStableOutputs`'s asset branch has no amount floor. [5](#0-4) 
2. Over time, thousands of unspent `outputs` rows accumulate for `(address=A, asset=X)`.
3. A legitimate trigger causes AA `A` to attempt sending a payment message in asset `X` via `sendUnit()`/`completePaymentPayload()`.
4. `readStableOutputs` returns all dust rows (no `LIMIT`); `iterateUnspentOutputs` loops over all of them, appending to `payload.inputs`, until either the message/unit size limits are exceeded (bounce) or excessive processing time/DB load occurs on every node validating/composing this unit. [2](#0-1)

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
