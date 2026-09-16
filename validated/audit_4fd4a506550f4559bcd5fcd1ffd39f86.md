### Title
Unbounded custom-asset dust outputs sent to an AA can permanently prevent it from spending that asset — ([File: aa_composer.js])

### Summary
This is the same bug class as Covalent M‑1: an unprivileged actor can grow an array/record set tied to a victim's identity with no bound, and a hard limit elsewhere then makes a critical state-changing operation for that victim permanently unusable. In ocore, the "validator unstaking array" analog is the set of unspent custom-asset outputs sitting at an AA's address: `handleTrigger`'s payment-composition logic filters out dust only for the base asset, not for custom assets, and later forces the AA-generated payment to include *all* matching unspent outputs with no cap, unlike ordinary user transactions.

### Finding Description
When an AA composes an outgoing payment for a non-`base` asset, `readStableOutputs`/`readUnstableOutputsSentByAAs` select unspent outputs of that asset at the AA's address and hand them to `iterateUnspentOutputs`, which pushes every row it visits into `payload.inputs` with no artificial ceiling on the number of inputs collected: [1](#0-0) [2](#0-1) 

The dust filter that exists for the base asset (`amount>=FULL_TRANSFER_INPUT_SIZE`) is explicitly *not* applied to custom assets — the `asset` branch of the WHERE clause has no minimum-amount condition: [3](#0-2) 

Crucially, when the resulting unit is validated in `validatePaymentInputsAndOutputs`, the normal cap on the number of payment inputs is explicitly skipped for AA-generated units: [4](#0-3) 

Any unprivileged unit poster can send arbitrarily many outputs of a tiny amount (e.g. `amount=1`) of a given custom asset to a target AA address — this is an ordinary payment message, requiring no special privilege, exactly like the Covalent bug where any delegator could push into another validator's `Unstaking` array. Because there is no per-asset dust threshold and no input cap for AA payments, once enough dust outputs accumulate, any subsequent attempt by the AA to pay out that asset (`iterateUnspentOutputs` must walk through, and `completePaymentPayload` must include, all of them to reach `bFound`) will keep growing `payload.inputs`/`objUnit` until the composed unit becomes oversized or otherwise fails validation/hard limits (e.g. `constants.MAX_UNIT_LENGTH`, `constants.MAX_MESSAGES_PER_UNIT`, or downstream commission/size checks), causing `validateAndSaveUnit` to fail and the trigger to bounce every time this code path is hit. Since the dust outputs are never marked spent on a failed/bounced attempt, the condition is permanent and self-reinforcing — the AA can never successfully compose a valid outgoing payment of that asset again.

### Impact Explanation
This freezes any custom asset balance the AA holds (and any future logic depending on paying it out), exactly analogous to "Validator can be permanently stuck" in the source report, but landing squarely in the explicitly accepted impact class of "AA fund loss or freezing." Any AA that issues, exchanges, or forwards a custom asset to third-party addresses (e.g., DEX/AMM-style AAs, token-wrapping AAs) is exposed: an attacker with negligible cost (dust amounts of that asset, or self-issued asset dust if the AA accepts any asset it doesn't control the issuance of) can render the AA permanently unable to pay that asset out, freezing user/protocol funds inside the AA indefinitely.

### Likelihood Explanation
The attack requires only posting ordinary payment units carrying many small-amount outputs of the targeted custom asset to the victim AA's address — a capability available to any unit poster/AA trigger sender, with no special access, no malicious node/hub involvement, and no reliance on private-key compromise. The precondition is that the AA at some point needs to spend the polluted asset via a normal `payment` message in its bytecode, which is a common AA pattern (any AA managing a custom asset balance for users). This makes exploitation straightforward and repeatable at low cost.

### Recommendation
- Apply a dust-amount floor to custom-asset outputs the same way it is applied to base-asset outputs in `readStableOutputs`/`readUnstableOutputsSentByAAs`, so tiny outputs below a bytes-equivalent-cost threshold are ignored by AA input selection.
- Reinstate (or add an AA-specific) cap on the number of inputs an AA-generated payment message may consume (mirroring `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE`), and make `completePaymentPayload`/`iterateUnspentOutputs` stop and either issue a partial payment across multiple responses or fail gracefully with a specific error rather than growing without bound.
- Consider a maintenance/consolidation mechanism analogous to what the Covalent README promised ("transfer without unstakings"): a controlled way to sweep/merge many small AA-asset outputs into fewer, larger ones without requiring the AA to spend all of them in a single oversized unit.

### Proof of Concept
1. Deploy or pick an existing AA that, per its bytecode, will at some point send a `payment` message paying out `ASSET_X` (a custom, non-base asset) to some address (e.g., an exchange/vault AA).
2. As an unprivileged attacker, repeatedly post ordinary units transferring `ASSET_X` in outputs of amount `1` (or another dust amount) to the AA's address — hundreds or thousands of such outputs, well beyond any reasonable value threshold. Nothing in `validatePaymentInputsAndOutputs`/asset validation prevents ordinary users from sending such dust, and `readStableOutputs`'s WHERE clause (`aa_composer.js:1149`) has no minimum-amount filter for non-base assets to reject them from being picked up later.
3. Trigger the AA path that causes it to compose an outgoing `payment` message of `ASSET_X`. `iterateUnspentOutputs`/`completePaymentPayload` (`aa_composer.js:1102-1245`) will attempt to consume all matching unspent outputs (no cap, since `validation.js:2137` exempts AA units from `MAX_INPUTS_PER_PAYMENT_MESSAGE`), producing an oversized/otherwise-invalid unit that fails `validateAndSaveUnit`, causing the trigger to bounce.
4. Confirm that on every subsequent trigger requiring the AA to spend `ASSET_X`, the same dust outputs are re-selected (they were never marked spent) and the payment composition fails again — the AA is permanently unable to move `ASSET_X`, freezing any balance of it inside the AA.

Note: I could not directly inspect the full body of `bounce()` in `aa_composer.js` or the exact point where unit-size/message-count hard limits (`constants.MAX_UNIT_LENGTH`, `constants.MAX_MESSAGES_PER_UNIT`) are enforced for AA-composed units within the available index; this should be verified in a full checkout to precisely characterize which hard limit is hit first and confirm the failure is unrecoverable rather than merely degraded performance.

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

**File:** validation.js (L2136-2138)
```javascript
	var total_input = 0;
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
```
