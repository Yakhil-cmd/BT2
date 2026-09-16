### Title
An attacker can permanently freeze an AA's asset balance by dusting it with unbounded tiny outputs, causing `iterateUnspentOutputs` to exceed `MAX_INPUTS_PER_PAYMENT_MESSAGE` - (File: `aa_composer.js`)

### Summary
`aa_composer.js`'s `sendUnit()` logic that composes an AA's outgoing payment collects unspent outputs of the AA's own address by running an unbounded SQL query (no `LIMIT`) and then feeding every returned row into `iterateUnspentOutputs()`, which pushes one `input` per row with no cap on the number of inputs added. Any unprivileged user can repeatedly pay tiny amounts of a given asset (or a custom asset with no dust filter) to an AA address across many separate units over time, growing the number of unspent outputs held by that AA for that asset without bound. When the AA later needs to spend that asset (or base coins, in the base-asset dust-filtered case exhausted with many-but-still-large-enough outputs), `iterateUnspentOutputs` will include far more inputs than `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` allows, producing an invalid unit that fails validation, permanently preventing the AA from spending/bouncing that asset — a fund-freezing analog of the CrabNetting "many small deposits create unprocessable state" bug class.

### Finding Description
In `aa_composer.js`, `completePaymentPayload()` builds the payment message for an AA response by calling: [1](#0-0) 

`readStableOutputs()` and `readUnstableOutputsSentByAAs()` query all unspent outputs of the AA address for a given asset with no `LIMIT` clause: [2](#0-1) 

Note that for the base asset there is a dust filter (`amount>=FULL_TRANSFER_INPUT_SIZE`), but for any custom asset there is **no dust/amount filter at all** — any positive amount output counts. The rows are then fed into `iterateUnspentOutputs()`: [3](#0-2) 

This loop unconditionally does `payload.inputs.push(input)` for every row returned by the unbounded query, with no check against `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE`. If an attacker sends the AA a large number of tiny-amount payments of some asset (each in a separate, cheap unit — analogous to CrabNetting's repeated small `depositUSDC`/`withdrawUSDC` calls creating unbounded queue growth), the AA's own address will accumulate an unbounded number of unspent outputs for that asset. As soon as any AA logic path attempts to send out that asset (even a partial amount, or a "send all" output), `sendUnit()` will pull in far more inputs than a single payment message may legally contain, producing a unit that is rejected by consensus-level input-count limits (`MAX_INPUTS_PER_PAYMENT_MESSAGE`, referenced in `validation.js` and `constants.js`). Because the query has no ordering/limit strategy that skips already-dusted outputs and no mechanism exists to "advance" past them (the CrabNetting report's exact recommended fix — an index-advancing function — is absent here too), every subsequent attempt by the AA to spend that asset's balance will keep re-selecting the same oversized unspent-output set and keep failing/bouncing, exactly mirroring the referenced report's "always fails" DoS condition on `depositAuction()`/`withdrawAuction()`.

### Impact Explanation
This permanently locks the affected asset balance held by the AA: any user-value-sensitive trigger flow that needs to make a payment of the dusted asset (e.g., forwarding proceeds, refunds, swap payouts) will produce an unspendable unit and bounce, so those funds become permanently inaccessible from the AA's own logic. Because oscript/AA execution is a core mechanism reachable by any unprivileged unit poster (the attacker only needs to send ordinary payment messages to the AA's address, no special privileges), this satisfies the "AA fund loss or freezing" impact criterion.

### Likelihood Explanation
The attack requires only that the attacker be able to author transfer messages paying arbitrarily small amounts of an asset to the target AA — a standard, unprivileged action available to any wallet holder. Because each attack step (one tiny payment) is a cheap, self-contained unit, the attacker can accumulate the required unbounded unspent-output count over an arbitrary number of transactions/blocks, with no protocol-level rate limiting of how many distinct tiny outputs one address may receive from independent senders. The likelihood is high for any AA whose logic sends out non-base assets it doesn't strictly control minting/dust rules for.

### Recommendation
- Add a `LIMIT` to `readStableOutputs`/`readUnstableOutputsSentByAAs` bounded by `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` (minus reserved slots for change/asset-issuance), and stop `iterateUnspentOutputs` once that many inputs have been added, falling back to partial spends or a graceful error rather than composing an invalid oversized unit.
- Apply a dust/minimum-amount filter for custom-asset unspent outputs analogous to the one already used for the base asset, to prevent cheap accumulation of a huge output count.
- Consider providing a maintenance mechanism (mirroring the report's suggested "advance index" fix) that lets an AA consolidate/sweep small dust outputs into fewer, larger ones outside of the time-critical payment-composition path, so a dusted asset balance can be recovered rather than permanently unspendable.

### Proof of Concept
1. Deploy/identify an AA that, at some point in its logic, sends payments of a custom asset `X` back to users (e.g., a swap/vault AA).
2. Attacker repeatedly sends the AA address many separate units, each paying a minimal amount (e.g., 1 unit) of asset `X` to the AA, until the total unspent-output count for asset `X` at the AA's address exceeds `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE`.
3. Trigger the AA logic path that causes it to send out asset `X` (even a small amount, or a send-all payout).
4. `sendUnit()` → `completePaymentPayload()` → `readStableOutputs()`/`readUnstableOutputsSentByAAs()` (unbounded query) → `iterateUnspentOutputs()` (unbounded push) build a payload with more inputs than the network-wide per-message input limit allows.
5. Unit composition/validation fails (input-count limit exceeded), so the trigger bounces; because the same oversized unspent-output set is selected again on every retry, this path becomes permanently unusable, freezing the AA's asset-`X` balance.

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
