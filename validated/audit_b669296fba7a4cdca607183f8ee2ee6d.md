## Finding [1](#0-0) 

### Title
Unbounded loop over attacker-inflatable asset outputs when an AA composes a payment response - (File: aa_composer.js)

### Summary
When an Autonomous Agent (AA) composes a payment response, `completePaymentPayload`'s `readStableOutputs`/`readUnstableOutputsSentByAAs` queries fetch *all* unspent outputs of the paying address for the target asset with no `LIMIT` clause, and `iterateUnspentOutputs` then loops over every returned row in JavaScript on every full node. [2](#0-1)  For the base-byte asset, a minimum output amount (`FULL_TRANSFER_INPUT_SIZE`) is enforced specifically to prevent a "dust attack: spamming the AA with very small outputs", but that dust filter is only applied to the base asset case, not to custom (non-base) assets. [3](#0-2) 

### Finding Description
Any unprivileged unit poster can send many tiny-value custom-asset outputs to an AA address (custom-asset payments have no minimum-amount/dust filter, unlike bytes). When that AA later needs to spend that asset — e.g. producing a `send_all` response or otherwise paying out in that asset — `completePaymentPayload` calls `readStableOutputs`/`readUnstableOutputsSentByAAs`, whose SQL query has no `LIMIT` and no per-output minimum-amount condition for non-base assets: `"...address=? AND asset="+conn.escape(asset)+" AND is_spent=0..."` [4](#0-3) . `iterateUnspentOutputs` then iterates every one of these rows synchronously in JS, pushing an input per row into `payload.inputs`, and for the `send_all_output` case explicitly does not break out of the loop early (`if (send_all_output) continue;`), forcing it to consume the *entire* result set rather than stopping once the target amount is reached. [5](#0-4) 

This is structurally the same bug class as the reported `LiquidationBot::fetchUnhealthyAccounts`: an attacker-controlled collection size (here, the number of tiny custom-asset outputs sent to the AA) drives an unbounded loop that every node must execute deterministically to process the trigger and validate the resulting response unit.

### Impact Explanation
Because AA trigger handling and response composition are executed identically by every full node to reach consensus on the response unit, an attacker can inflate the number of unspent custom-asset outputs at a target AA's address to a very large number (limited only by the cost of issuing many tiny-amount payment messages, which is cheap since custom-asset dust has no minimum-size filter). When the AA is triggered to send/forward that asset (including a `send_all` payment), every node performing/validating the response must iterate over this potentially huge unbounded set in JS, causing excessive CPU/memory consumption and response-composition delay or failure on every node handling that AA. This can degrade or halt processing of that AA (denial of service against the AA and, transitively, its users/funds), and in aggregate load on the network's synchronous AA-response pipeline. Note that unlike Solidity gas, there is no hard per-operation complexity metering for this DB-driven loop, so it isn't capped the way oscript formula complexity (`MAX_COMPLEXITY`/`MAX_OPS`) is.

### Likelihood Explanation
Likelihood is Medium-to-High: the attack requires no privileged access — any unit poster can send arbitrarily many tiny custom-asset payment units to a known AA address (each such payment is a normal, valid unit), and the AA can be triggered normally afterward causing the affected code path to execute. The known dust-mitigation comment already present in the code for bytes confirms the developers were aware of a similar risk, but the same mitigation is absent for custom assets.

### Recommendation
Apply a minimum spendable-output-amount ("dust") condition analogous to `FULL_TRANSFER_INPUT_SIZE` to the custom-asset branch of `readStableOutputs`/`readUnstableOutputsSentByAAs`, and/or enforce a hard `LIMIT` (e.g., bounded by `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE`, which is already used to bound inputs in the general wallet coin-selection code `inputs.js`) on the number of rows fetched/iterated per payment message, ensuring `iterateUnspentOutputs` cannot process an attacker-inflated number of rows in a single AA response composition.

### Proof of Concept
1. Deploy/target an AA that, on some trigger condition, responds with a `send_all` (or otherwise asset-spending) payment message for a custom asset `X` from its own balance.
2. As an unprivileged attacker, repeatedly send the AA address many (e.g., tens of thousands) minimal-amount payment units of asset `X` (no dust filter blocks this for non-base assets, unlike bytes).
3. Trigger the AA to produce the asset-`X` payment response.
4. Observe that `completePaymentPayload`/`readStableOutputs` returns all of these tiny outputs with no `LIMIT`, and `iterateUnspentOutputs` loops over the full set (especially forced to continue fully for `send_all_output`), causing excessive processing time/memory on every node executing/validating this AA response — degrading or effectively denying further processing of that AA. [6](#0-5)

### Citations

**File:** aa_composer.js (L1102-1173)
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
