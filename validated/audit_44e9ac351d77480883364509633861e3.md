### Title
Bounce fee minimum does not account for oversize/tps fees actually charged when composing the bounce response, causing the AA to pay the shortfall from its own balance - (File: aa_composer.js, aa_validation.js)

### Summary
The Astaria bug is that `liquidationInitialAsk` (a hard-coded minimum used to bound how much debt/reward is later deducted) is validated against a fixed floor that ignores a fee (the liquidator reward) that will actually be charged when the position is later liquidated — so the shortfall is silently absorbed by other stakeholders in the stack. The analogous pattern in ocore is the AA `bounce_fees.base` minimum: `aa_validation.js` only enforces that `bounce_fees.base >= constants.MIN_BYTES_BOUNCE_FEE` [1](#0-0) , and at trigger time `handleTrigger` only checks that the trigger sent at least `bounce_fees.base` bytes [2](#0-1) . Neither check accounts for the real, size-dependent network fees (`oversize_fee`, `tps_fee`, headers/payload commission) that will actually be charged when the bounce (or any response) payment unit is composed and sent.

### Finding Description
When a trigger's balance is insufficient to run the AA formula successfully, the AA "bounces" and returns `trigger.outputs[asset] - bounce_fees[asset]` back to the sender [3](#0-2) . The static per-AA `bounce_fees.base` value is only required to be ≥ `constants.MIN_BYTES_BOUNCE_FEE` at definition-validation time [4](#0-3) , and the only run-time check is that the trigger's declared output covers this static number [5](#0-4) .

However, the actual cost of composing and sending the resulting response/bounce unit is computed later in `sendUnit`/`completePaymentPayload`, where a size-dependent `oversize_fee` (and, depending on version, `tps_fee`) is computed from the real unit size and added on top of `headers_commission`/`payload_commission` [6](#0-5) . This oversize fee is not a fixed constant — it grows with the size of the AA's local storage/state and with the last-ball MCI-derived fee schedule, and it is not reflected in `MIN_BYTES_BOUNCE_FEE` or in the up-front `bounce_fees.base` check.

Consequently, when the trigger sends exactly the declared `bounce_fees.base` (the bare minimum accepted by validation), and the actual response/bounce unit's real network fee (`oversize_fee`/`tps_fee`) exceeds the fixed bounce fee margin, the difference has to be funded from somewhere else: `completePaymentPayload` will pull additional inputs from the AA's own balance to cover the deficit [7](#0-6) . This is structurally identical to the Astaria issue: a minimum threshold (`liquidationInitialAsk` / `bounce_fees.base`) is validated without including a fee that is actually incurred later (liquidator reward / oversize+tps fee), so that fee ends up being paid out of funds belonging to other parties (junior vault lenders / other AA balance holders), rather than by the party that should be bearing it (the liquidated borrower / the under-funded trigger sender).

### Impact Explanation
Because the AA absorbs the unaccounted fee from its own balance rather than from the bounced/insufficient trigger, funds belonging to other users of the same AA (e.g. depositors, LPs, or any address whose funds sit in the AA's balance) can be silently drained to cover fees that should have been charged to the specific under-funded trigger. Over many bounced/low-value triggers, an attacker could repeatedly send triggers funded at exactly `MIN_BYTES_BOUNCE_FEE`/`bounce_fees.base` to force the AA to eat the oversize/tps-fee delta from its own balance on every bounce, draining AA-held user funds — a fund-loss/fund-freezing condition for the AA and its legitimate depositors.

### Likelihood Explanation
This requires the AA to have a storage/state footprint (or a fee schedule) such that the real `oversize_fee`/`tps_fee` incurred while composing the bounce unit exceeds the margin baked into `bounce_fees.base`. `bounce_fees.base` is attacker/AA-author controlled but only bounded below by `constants.MIN_BYTES_BOUNCE_FEE`; nothing prevents an AA from being defined (or evolving via growing state) with a `bounce_fees.base` close to that constant floor while its real oversize fee grows over time as `storage_size` grows, making the discrepancy achievable by any unprivileged poster of triggers to any deployed AA whose bounce fee is set near the minimum.

### Recommendation
Include the AA's actual size-dependent network cost (worst-case `oversize_fee`/`tps_fee` given the AA's current `storage_size`) in the minimum acceptable `bounce_fees.base`, either by dynamically recomputing the effective minimum bounce fee at trigger time (as `MIN_BYTES_BOUNCE_FEE + max_possible_oversize_fee`) or by re-validating, before bouncing, that the declared bounce fee still covers the unit's projected fees; if not, fail closed (treat as insufficient funds) instead of silently drawing the shortfall from the AA's own balance.

### Proof of Concept
Not independently reproduced in this analysis (would require constructing an AA whose `storage_size` is large enough that `storage.getOversizeFee(...)` exceeds the margin between `bounce_fees.base` and `MIN_BYTES_BOUNCE_FEE`, then sending a trigger funded at exactly `bounce_fees.base` and observing that the AA's balance decreases by more than the nominal bounce fee when `sendUnit`/`completePaymentPayload` pulls extra inputs to cover `oversize_fee` [8](#0-7) ).

### Citations

**File:** aa_validation.js (L748-759)
```javascript
	if ('bounce_fees' in template){
		if (!isNonemptyObject(template.bounce_fees))
			return callback("empty bounce_fees");
		for (var asset in template.bounce_fees){
			if (asset !== 'base' && !isValidBase64(asset, constants.HASH_LENGTH))
				return callback("bad asset in bounce_fees: " + asset);
			var fee = template.bounce_fees[asset];
			if (!isNonnegativeInteger(fee) || fee > constants.MAX_CAP)
				return callback("bad bounce fee: "+JSON.stringify(fee));
		}
		if ('base' in template.bounce_fees && template.bounce_fees.base < constants.MIN_BYTES_BOUNCE_FEE)
			return callback("too small base bounce fee: "+template.bounce_fees.base);
```

**File:** aa_composer.js (L928-944)
```javascript
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
```

**File:** aa_composer.js (L1083-1136)
```javascript
			const paid_temp_data_fee = objectLength.getPaidTempDataFee({ messages });
			const bChargeOversizeFee = (mci >= constants.v4UpgradeMci && is_base);
			// AA-generated units pay the oversize fee based on the unit size excluding its payment messages;
			// this doesn't change as we add more inputs to the payment message, so calculate it only once
			const oversize_fee_excluding_payments = (bChargeOversizeFee && mci >= constants.pemCurvesFixMci)
				? storage.getOversizeFee(objUnit.headers_commission + objectLength.getTotalPayloadSize({ ...objUnit, messages: messages.filter(message => message.app !== 'payment') }) - paid_temp_data_fee, last_ball_mci)
				: null;
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
```

**File:** aa_composer.js (L1851-1859)
```javascript
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```
