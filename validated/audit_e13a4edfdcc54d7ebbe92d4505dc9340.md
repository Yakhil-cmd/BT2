### Title
Unbounded UTXO consumption when an AA pays out a custom asset lets any user permanently freeze that asset's payouts - (File: `aa_composer.js`)

### Summary
When an Autonomous Agent (AA) sends a `payment` message, `aa_composer.js` builds the payload by pulling unspent outputs of the target asset that belong to the AA's address and accumulating them, oldest first, until the target amount is covered [1](#0-0) . The code explicitly notes that base-asset ("byte") outputs smaller than the input's own footprint are filtered out "to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond" [2](#0-1) . That anti-dust filter, however, only applies when `asset` is falsy (base asset); for any custom asset the `WHERE` clause has no minimum-amount condition at all [3](#0-2) [4](#0-3) .

### Finding Description
`iterateUnspentOutputs()` walks the rows returned by `readStableOutputs()`/`readUnstableOutputsSentByAAs()` in a fixed, deterministic order (`main_chain_index, unit, output_index`) and keeps adding each output as a new payment `input` until the running `total_amount` reaches `target_amount` [5](#0-4) . There is no cap on the number of inputs that can be added, and — unlike the base-asset case — there is no minimum-amount filter for custom assets, so an attacker can pre-fund the AA's address with an arbitrarily large number of 1-unit (or otherwise minimal) outputs of that asset before or between AA invocations.

This is directly analogous to the reported NFTX bug class: the zap contracts assumed that "the balance visible to the vault-minting logic" reflects only legitimate flows, and any unprivileged party could break that assumption by donating tokens directly to the contract, permanently breaking an exact-state check for everyone. In ocore, the AA composer assumes that the unspent outputs of an asset held by the AA are a small, well-behaved set that it can freely enumerate and consume when constructing a payment; any AA trigger sender or asset holder can violate that assumption by fragmenting the AA's asset balance into many tiny outputs. Any legitimate user who then triggers a payout in that asset forces the composer to walk through (and include as inputs) all the attacker-created dust outputs before it can reach an amount that satisfies `target_amount`, because outputs are consumed in a fixed chronological order rather than by size. If the number of outputs needed to reach the target amount is large enough, the resulting payment message (and hence the whole response unit) grows past the protocol's size/complexity limits, so the composed response fails and the AA bounces — refunding the trigger but not undoing the attacker's dust outputs, which remain unspent and will be consumed by the composer again on the next legitimate call, since consumption always proceeds from the oldest output.

### Impact Explanation
Because the dust remains unspent after a failed/bounced attempt (nothing was ever spent, the response unit was never built successfully), every subsequent trigger that tries to pay out that same asset will encounter the exact same (or worse, growing) backlog of dust UTXOs at the front of the queue. This can make an AA permanently unable to pay out a given asset to anyone, i.e., a persistent freezing of AA funds for all users of that asset — matching the "AA fund freezing" impact category. The cost to the attacker is only the negligible amount of the asset (which can be 1 unit each) times the number of outputs needed to overwhelm the message-size limits, and posting many tiny-output units is cheap relative to the permanent damage caused.

### Likelihood Explanation
Any user who can send outputs of the target asset to the AA's address — which is by definition true for any transferable asset the AA is designed to receive (deposits, share tokens, LP tokens, etc.) — can carry out this attack with ordinary, unprivileged unit posting; no special permission, oracle, or witness involvement is required. The mitigation comment at `aa_composer.js` line 1144 shows the developers were already aware of and defended against this exact griefing pattern for the base asset, but the same protection was not extended to non-base assets, leaving a clear, reachable gap.

### Recommendation
Apply a minimum-output-size / dust filter for non-base assets analogous to the one already used for the base asset (e.g., skip outputs whose amount is smaller than some fraction of the marginal input cost, or below a configurable dust threshold per asset). Additionally, consider capping the number of inputs a single payment message can accumulate and preferring larger outputs first (rather than strict chronological order) when selecting UTXOs to satisfy `target_amount`, so that a handful of legitimate, adequately sized outputs can be spent without being forced to sweep in attacker-created dust.

### Proof of Concept
1. Attacker identifies an AA that pays out asset `X` to trigger senders (e.g., a market maker or vault-style AA).
2. Attacker posts many units, each sending a tiny (e.g., 1-unit) output of asset `X` to the AA's address. Because the `readStableOutputs`/`readUnstableOutputsSentByAAs` queries for non-base assets have no minimum-amount filter [6](#0-5) [7](#0-6) , all of these dust outputs are eligible to be selected as payment inputs.
3. A legitimate user triggers the AA in a way that requires it to send out asset `X` (e.g., a withdrawal/exchange case as in the sample AMM AA pattern using `balance[$asset]` [8](#0-7) ).
4. `iterateUnspentOutputs()` walks the outputs in chronological order and is forced to include the attacker's dust outputs as inputs before it can accumulate enough amount to reach `target_amount` [5](#0-4) .
5. If the accumulated number of inputs pushes the payment message (and unit) past protocol size limits, the composed unit fails to validate/post and the AA bounces the trigger, leaving the dust outputs unspent for the next call to hit the same wall — permanently freezing payouts of asset `X` from that AA.

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

**File:** aa_composer.js (L1167-1172)
```javascript
					WHERE outputs.address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>="+FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND (main_chain_index>? OR main_chain_index IS NULL) \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY latest_included_mc_index, level, outputs.unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
```

**File:** test/samples/uniswap_like_market_maker.oscript (L102-123)
```text
			{ // exchange bytes to asset
				if: `{trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] == 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_asset_balance = round($p / balance[base]);
					$amount = $asset_balance - $new_asset_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```
