## Title
Dust-Output Griefing of AA Payment Composition Due to Missing Negligible-Amount Filter for Non-Base Assets - (File: `aa_composer.js`)

### Summary
When an Autonomous Agent (AA) composes an outgoing payment in response to a trigger, `aa_composer.js` gathers unspent outputs to fund the payment via `readStableOutputs()` / `readUnstableOutputsSentByAAs()` inside `completePaymentPayload()`. For the base asset, the code explicitly excludes tiny outputs (`amount>=FULL_TRANSFER_INPUT_SIZE`) with the comment "byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond" [1](#0-0) . This is the exact mitigation the external report recommends (a "negligible amount" threshold). However, this filter is applied only to base-asset (bytes) outputs; the same query for a custom asset has no amount floor at all [2](#0-1) , and the same is true of `readUnstableOutputsSentByAAs()` [3](#0-2) .

### Finding Description
`iterateUnspentOutputs()` consumes rows returned by these two query functions one at a time as inputs to the AA's outgoing payment message, adding `FULL_TRANSFER_INPUT_SIZE` to `size`/`net_target_amount` for every base-asset input consumed and growing the payment payload for every asset input consumed [4](#0-3) . Because non-base-asset outputs have no minimum-amount filter, an unprivileged attacker can post ordinary payment units sending a large number of dust-sized outputs of a given asset to an AA address. Any subsequent AA response that must spend the AA's holdings of that asset (e.g. a `send-all`/`amount:undefined` output, or any payout requiring the AA to sweep its balance) is forced by `readStableOutputs`/`iterateUnspentOutputs` to include every one of these dust inputs in the resulting unit, since the loop only stops once the target amount is reached and dust outputs contribute negligible value toward `target_amount` while still increasing unit size and hence the base-currency fee the AA must pay (`headers_commission`/`payload_commission`, and `getOversizeFee`) [5](#0-4) . If accumulating the dust makes the composed unit exceed the AA's spendable base-asset balance or size limits, the AA falls into the `'not enough funds for ' + target_amount + ' bytes'` bounce path [6](#0-5) , and for asset shortfalls into the `'not enough funds for ' + target_amount + ' of asset ' + asset` path [7](#0-6) , permanently disrupting that AA's ability to complete the fund-sweeping response — the same "dust donation disrupts a fund-removal/fund-sweep operation" bug class described in the external report.

### Impact Explanation
An attacker with no privileges can grief an AA by repeatedly donating dust amounts of any custom asset to it. This forces every future full-balance/send-all payout of that asset by the AA to bundle an ever-growing number of worthless inputs, inflating the transaction size and the byte-denominated fee the AA must self-fund. Once the accumulated dust makes fee payment infeasible, AA responses bounce, effectively freezing the AA's legitimate asset funds and breaking any application logic relying on the AA being able to fully sweep or forward its asset balance — a fund-freezing/denial-of-function impact directly comparable to the referenced NDC-removal disruption.

### Likelihood Explanation
The attack requires only the ability to post ordinary payment units to a known AA address holding or expected to hold a custom asset balance — something any unprivileged user can do cheaply and repeatedly (each dust unit costs only minimal bytes fee to the attacker while its effect on the victim AA compounds over many donations).

### Recommendation
Extend the existing dust-mitigation logic already applied to base-asset outputs (`amount>=FULL_TRANSFER_INPUT_SIZE` in `readStableOutputs`/`readUnstableOutputsSentByAAs`, `aa_composer.js` lines 1149 and 1167) to non-base assets as well, e.g. by introducing an asset-aware negligible-amount threshold (analogous to the referenced `maxNegligibleAmount`) so dust outputs of custom assets are ignored when composing AA responses, or by capping the number of inputs consumed per payment message independent of amount.

### Proof of Concept
1. Deploy or identify an AA that, in some response branch, sends a `send-all` (amount-less) payment output of a custom asset it holds.
2. As an attacker, send hundreds of very small (e.g. denomination-minimum) outputs of that asset to the AA's address in separate units over time.
3. Trigger the AA's send-all response; `completePaymentPayload()`'s `readStableOutputs`/`iterateUnspentOutputs` will pull in all of the attacker's dust outputs as inputs (no amount filter for non-base assets, `aa_composer.js:1149`), inflating the unit size and required byte fee.
4. Once the required byte fee exceeds the AA's spendable base-asset balance, the response bounces with `'not enough funds for ... bytes'` (`aa_composer.js:1231-1232`), demonstrating that the AA's legitimate payout is disrupted purely by unprivileged dust donations.

### Citations

**File:** aa_composer.js (L1090-1100)
```javascript
			var net_target_amount = payload.outputs.reduce(function (acc, output) { return acc + (output.amount || 0); }, size);
			let target_amount = net_target_amount + getOversizeFee(size);
			var bFound = false;

			function getOversizeFee(s) {
				if (!bChargeOversizeFee)
					return 0;
				if (mci < constants.pemCurvesFixMci)
					return storage.getOversizeFee(s - paid_temp_data_fee, last_ball_mci);
				return oversize_fee_excluding_payments;
			}
```

**File:** aa_composer.js (L1102-1114)
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

**File:** aa_composer.js (L1167-1167)
```javascript
					WHERE outputs.address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>="+FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
```

**File:** aa_composer.js (L1231-1232)
```javascript
					if (!asset)
						return cb('not enough funds for ' + target_amount + ' bytes');
```

**File:** aa_composer.js (L1236-1240)
```javascript
					issueAsset(function (err) {
						if (err) {
							console.log("issue failed: " + err);
							return cb('not enough funds for ' + target_amount + ' of asset ' + asset);
						}
```
