### Title
DoS: Custom-asset dust outputs sent to an AA are never filtered and are fully iterated/consumed on send-all, causing unbounded input accumulation and AA fund freezing - (File: `aa_composer.js`)

### Summary
`completePaymentPayload()`'s `readStableOutputs()`/`readUnstableOutputsSentByAAs()` helpers, used when an AA composes its response unit, explicitly apply a minimum-amount dust filter only for the base asset (`amount>=FULL_TRANSFER_INPUT_SIZE`), but apply none for custom (non-base) assets (`asset=?` with no amount floor). [1](#0-0) 

### Finding Description
Any unprivileged user can post ordinary payment units sending arbitrarily many extremely small (dust) outputs of an existing custom asset to an AA address; these units only need to pass normal payment validation, which has no per-output minimum-amount check for non-base assets. [2](#0-1) 

When the AA later needs to spend that asset (in particular, a `send-all` output for that asset), `completePaymentPayload()` fetches unspent outputs for the AA in that asset with `readStableOutputs`/`readUnstableOutputsSentByAAs` (no `LIMIT`, no minimum-amount filter for non-base assets) and then `iterateUnspentOutputs()` walks every returned row. [3](#0-2) 
For a `send_all_output`, the loop does not `break` once the target is met — it `continue`s and keeps pushing every fetched row into `payload.inputs` — so all dust outputs accumulated for that asset are consumed in a single iteration. [4](#0-3) 

Crucially, the anti-spam cap on the number of inputs per payment message is explicitly bypassed for AA-generated units: `validatePaymentInputsAndOutputs()` only enforces `MAX_INPUTS_PER_PAYMENT_MESSAGE` `&& !objValidationState.bAA`. [5](#0-4) [6](#0-5) 

This is structurally the same bug class as the reported issue: an attacker-controllable, unbounded-growth collection (per-trader open positions in the report; per-AA-address unspent dust outputs of a custom asset here) is iterated in full inside a critical state-transition function (`_realizePnl()` there; `completePaymentPayload()`/AA trigger handling here), with no cap on the collection's size before the loop runs.

### Impact Explanation
An attacker can spam an AA address with thousands/millions of cheap dust outputs in a custom asset (cost is only the minimal transaction fee per unit, and outputs of any positive integer amount are accepted). Whenever the AA subsequently attempts a `send-all` payment in that asset (a common oscript idiom), the AA composer must fetch and iterate over all of these unspent outputs, then build a resulting response unit whose `payload.inputs` array contains all of them. This:
- Produces a unit whose size may exceed `MAX_UNIT_LENGTH` or otherwise fail commissioning/pickParents/oversize-fee logic, causing `bounce()`, so the AA becomes permanently unable to fulfill triggers requiring a send-all in that asset — an on-chain, unprivileged, and repeatable freezing of AA funds/functionality.
- Even if it doesn't hard-fail, the growing per-trigger DB query, JS-side iteration, and JSON serialization work scale with attacker-supplied input count, degrading throughput of AA processing (which runs synchronously per unit during mci stabilization) for all nodes computing the same AA trigger, i.e., a shared computational cost imposed by one unprivileged party on every full node.

This matches the "Accept" criteria of AA fund loss/freezing and a node's inability to confirm/execute a specific unit's AA responses.

### Likelihood Explanation
Medium-High: any user can define or use an existing publicly-transferable custom asset, and send unlimited tiny-amount payments to any AA address without any special privilege, cost is negligible relative to the number of outputs that can be generated across many transactions over time, and many production AAs implement send-all patterns (e.g., forwarding leftover asset balances) that would trigger the vulnerable code path.

### Recommendation
Apply the same anti-dust minimum-amount filter used for the base asset (`amount>=FULL_TRANSFER_INPUT_SIZE`) to non-base assets in `readStableOutputs()`/`readUnstableOutputsSentByAAs()`, or cap the number of rows fetched/consumed per asset (e.g., add `LIMIT MAX_INPUTS_PER_PAYMENT_MESSAGE` to the SQL and stop enforcing the `!objValidationState.bAA` exemption in `validatePaymentInputsAndOutputs()` for the input count check), and consider periodic consolidation/sweeping of dust outputs credited to AA balances so per-asset unspent-output sets held by an AA cannot grow unbounded from unprivileged senders.

### Proof of Concept
1. Attacker (or anyone) creates or uses an existing public, transferable custom asset `A`.
2. Attacker crafts and posts N ordinary units, each sending a 1-unit-amount output of asset `A` to AA address `X` (each unit only needs to satisfy normal payment validation, which imposes no minimum amount for non-base assets — see `validation.js:2151-2160`).
3. Once these units stabilize, `X`'s custom-asset `A` balance/unspent-output set contains N tiny outputs.
4. Attacker (or a normal user) triggers AA `X` in a way that causes it to execute a `send-all` payment message for asset `A` in its oscript logic.
5. `completePaymentPayload()` calls `readStableOutputs()`/`readUnstableOutputsSentByAAs()` (no minimum-amount filter, no `LIMIT` for asset `A`), returning all N dust rows; `iterateUnspentOutputs()` pushes all N into `payload.inputs` because `send_all_output` prevents early `break`.
6. The resulting `payload.inputs.length` is not checked against `MAX_INPUTS_PER_PAYMENT_MESSAGE` because `objValidationState.bAA` is true, so validation does not reject the oversized inputs array; the response unit either fails to be posted (bouncing the AA, freezing its response capability for that asset) or imposes a heavy, attacker-scaled processing cost on every node computing the AA's trigger.

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

**File:** validation.js (L2137-2138)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
```

**File:** validation.js (L2151-2160)
```javascript
	for (var i=0; i<payload.outputs.length; i++){
		var output = payload.outputs[i];
		if (!isNonemptyObject(output))
			return callback("output must be a non-empty object");
		if (hasFieldsExcept(output, ["address", "amount", "blinding", "output_hash"]))
			return callback("unknown fields in payment output");
		if (!isPositiveInteger(output.amount))
			return callback("amount must be positive integer, found "+JSON.stringify(output.amount));
		if (output.amount > constants.MAX_CAP)
			return callback("output too large: " + output.amount);
```

**File:** constants.js (L47-47)
```javascript
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
```
