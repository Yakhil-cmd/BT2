### Title
Missing dust-output filter for custom assets in AA fund composition allows fee-griefing drain of AA base-currency balance - (File: aa_composer.js)

### Summary
When an Autonomous Agent (AA) composes a response unit that needs to pay out a non-base (custom) asset, `sendUnit()`'s inner helper `completePaymentPayload()` selects unspent outputs of that asset to use as inputs via `readStableOutputs()` / `readUnstableOutputsSentByAAs()`. For the base asset, these queries explicitly exclude outputs smaller than `FULL_TRANSFER_INPUT_SIZE` specifically to prevent a dust-spam attack, but this filter is only applied when `asset` is null (base), not when a custom asset is specified. [1](#0-0) 

### Finding Description
The comment in the code explicitly documents the intended protection: "byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond." [2](#0-1) 

However, the SQL condition only applies `amount>=FULL_TRANSFER_INPUT_SIZE` in the branch where `asset` is falsy (i.e., base bytes): `"WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+...`. When `asset` is truthy (a custom asset), the query has no minimum-amount condition at all, so every unspent output of that asset — no matter how small — is a candidate input. [3](#0-2) [4](#0-3) 

Furthermore, the per-input size/fee accounting in `iterateUnspentOutputs()` only increases `net_target_amount`/`size` by `FULL_TRANSFER_INPUT_SIZE` when `is_base` is true; for non-base assets this increment never happens, so consuming many extra custom-asset inputs is not reflected in the byte-fee target the AA charges itself when computing change for the base payment message. [5](#0-4) 

An attacker who deals with an AA that holds/tracks a custom asset (e.g. a DEX/vault-style AA that accepts a token and later pays it back out, similar to the reported SolverVault pattern) can pre-seed the AA's address with a very large number of dust-sized outputs of that asset (each output only needs to satisfy the network's own minimal-output validation, which is far smaller than `FULL_TRANSFER_INPUT_SIZE`). When the AA is later triggered to send that asset back (e.g. on a legitimate user's withdrawal/swap), `iterateUnspentOutputs()` will greedily consume outputs in deterministic `ORDER BY main_chain_index, unit, output_index`, potentially pulling in many of the attacker's dust inputs before reaching the target amount, each adding real bytes (and thus real headers/payload commission, paid from the AA's own base-currency storage) to the response unit without a matching per-input fee charged against the triggering payment.

### Impact Explanation
This lets an unprivileged attacker inflate the true byte cost of AA responses whenever the AA spends a custom asset it holds, causing the AA's base-currency balance to be drained by disproportionate transaction fees relative to the actual value moved — an AA fund loss/deficit, mirroring the original SolverVault "spam small withdraws to run a deficit" bug class. In severe cases this can degrade or halt an AA's ability to fund its own future responses (bounce fees / storage_size requirements), effectively freezing legitimate user withdrawals until the AA is topped up.

### Likelihood Explanation
Exploitation only requires the ability to send ordinary payment units containing the target custom asset to the victim AA's address (no privileged role needed), and any AA that stores/forwards a custom asset (a common DeFi pattern: deposit/withdraw vaults, DEXes, bridges implemented as AAs) is a plausible target. The attack cost to the attacker is asset transaction fees for many tiny-value outputs, which is cheap relative to the AA's byte-fee loss, matching the original report's core economic asymmetry.

### Recommendation
Apply the same dust-avoidance minimum-amount filter used for base outputs to custom-asset outputs in `readStableOutputs()` and `readUnstableOutputsSentByAAs()` (e.g., require `amount >= some_minimum` scaled to the number of decimals/typical value of the asset, or cap the number of inputs consumed per response and charge the size cost proportionally), and make the byte-fee target (`net_target_amount`/`size`) in `completePaymentPayload()` correctly account for every consumed input regardless of asset, not just base-asset inputs.

### Proof of Concept
1. Deploy/trigger an AA (analogous to the sample vault AAs in this repo, e.g. `test/samples/order_book_exchange.oscript` or `a_bank_without_percent.oscript`, which hold and pay out a custom asset on withdraw) whose balance/logic tracks a custom asset per user. [6](#0-5) 
2. Attacker sends thousands of units to the AA's address, each carrying a single 1-unit output of the tracked custom asset, all confirmed/stable.
3. Attacker (or any user) triggers the AA's withdraw case for that asset; `sendUnit()` → `completePaymentPayload()` runs `readStableOutputs()` for the custom asset with no minimum-amount filter, and `iterateUnspentOutputs()` consumes many of the dust inputs to reach the withdrawal target. [7](#0-6) 
4. The resulting response unit is much larger than expected (many extra inputs), so its headers/payload commission — paid from the AA's base-currency balance — is disproportionately higher than what the triggering payment/bounce fee covers, draining the AA over repeated triggers.

### Citations

**File:** aa_composer.js (L1102-1116)
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

**File:** aa_composer.js (L1161-1172)
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
```

**File:** aa_composer.js (L1223-1230)
```javascript
			readStableOutputs(function (rows) {
				iterateUnspentOutputs(rows);
				if (bFound && !send_all_output)
					return sortOutputsAndReturn();
				readUnstableOutputsSentByAAs(function (rows2) {
					iterateUnspentOutputs(rows2);
					if (bFound)
						return sortOutputsAndReturn();
```

**File:** test/samples/order_book_exchange.oscript (L1-26)
```text
{
	messages: {
		cases: [
			{ // withdraw funds
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND trigger.data.amount <= var[$key]
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{trigger.data.asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{trigger.data.amount}"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var[$key] = var[$key] - trigger.data.amount;
						}`
					}
				]
			},
```
