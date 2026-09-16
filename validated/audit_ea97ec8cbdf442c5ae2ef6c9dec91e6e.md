### Title
Unbounded, unfiltered custom-asset dust outputs can permanently freeze an AA's ability to spend that asset - (File: aa_composer.js)

### Summary
`aa_composer.js`'s `completePaymentPayload()` picks inputs for an AA response by querying `outputs` for unspent, spendable coins of the address. For the base asset (bytes) the query filters out dust with `amount>=FULL_TRANSFER_INPUT_SIZE` ("byte outputs less than 60 bytes … are ignored to prevent dust attack"), but for any custom asset this floor is not applied at all, and there is no `LIMIT` on the number of rows returned. An attacker who can predict an AA's address in advance (e.g. a parameterized/counterfactual AA address, computed deterministically as `chash160(['autonomous agent', {base_aa, params}])` before the AA is ever posted) can pre-flood that address with a very large number of minimal custom-asset outputs. This mirrors the report's root cause: a deterministically-predictable future contract/address that an attacker pre-loads with a huge number of low-value units so that the victim's later, unavoidable operation over "all held items" becomes unbounded and can revert/stall/never complete.

### Finding Description
`readStableOutputs()`/`readUnstableOutputsSentByAAs()` in `aa_composer.js` build the SQL query for candidate coins: [1](#0-0) 

The dust-mitigation comment explicitly states the amount floor exists "to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond" - but the floor `AND amount>=FULL_TRANSFER_INPUT_SIZE` is applied only in the base-asset branch of the conditional (`asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE`). When `asset` is a custom (non-base) asset, the query has no minimum-amount clause and no `LIMIT`, so it can return an arbitrarily large row set.

`iterateUnspentOutputs()` then loops synchronously over every returned row to accumulate `total_amount`, pushing one input per row into `payload.inputs`: [2](#0-1) 

Because a custom-asset holding address is completely predictable ahead of time (any AA address - regular or parameterized - is just `chash160()` of its definition, and anyone can compute the future address of a base_aa+params pair before that parameterized AA is ever defined/posted), an attacker can:
1. Compute the target AA address off-chain.
2. Issue/acquire a custom asset the target AA is known (or expected) to hold or receive, or simply send many tiny outputs of an asset the AA already handles, directly to that address via ordinary payments - this requires no privilege, just an unprivileged unit poster sending a payment message.
3. Split the transfer into thousands of minimal (e.g. 1-unit) outputs to that address.

When the AA is later triggered and needs to spend or forward that asset (including an unavoidable `send-all` style operation or any payment message referencing that asset), `completePaymentPayload()` must call `readStableOutputs`/`readUnstableOutputsSentByAAs` and `iterateUnspentOutputs` over all of the attacker-planted rows, since there is no per-query row cap and no per-row value floor. This can blow past `payload.inputs` limits enforced later in unit validation (`inputs.js`/`validation.js` reference `MAX_INPUTS_PER_PAYMENT_MESSAGE`), causing the composed response to fail/bounce, or can make composition itself prohibitively expensive for the node executing the AA trigger.

### Impact Explanation
If the number of accumulated inputs required to satisfy a payment/send-all exceeds `MAX_INPUTS_PER_PAYMENT_MESSAGE`, the AA's outgoing payment for that asset can never be completed in a single response unit, so the AA becomes unable to move/forward the funds it holds in that asset - an AA fund-freezing condition analogous to the SinkManager being "stuck in current state" in the original report. Because the dust-outputs live in ordinary `outputs` rows tied to a predictable address, the attack is inexpensive relative to the potential freeze of the AA's custom-asset balance, and it can be executed by any unprivileged unit poster before the target AA (particularly a parameterized/counterfactual AA) is even deployed. This is a Medium-to-High severity griefing/DoS vector against AA-held custom-asset balances.

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to (a) know or predict the target AA address in advance, and (b) be able to send (or issue and send) many small-amount outputs of the relevant custom asset to it - both of which are ordinary, unprivileged operations (posting payment messages). Predicting addresses of parameterized/counterfactual AAs is straightforward since the address is a pure hash of `base_aa`+`params`/definition, requiring no special access. The main constraint is the attacker needs sufficient units of the specific custom asset, which limits the attack to AAs that deal in assets the attacker can acquire cheaply/in bulk (e.g., assets with no issuance cap, or assets the attacker legitimately trades).

### Recommendation
Apply the same anti-dust minimum-amount floor and/or a row `LIMIT` to the custom-asset branch of `readStableOutputs()`/`readUnstableOutputsSentByAAs()` that is already applied to the base-asset branch, and cap the number of inputs pulled per query (e.g., `ORDER BY amount DESC LIMIT <n>` as already done elsewhere for divisible-asset coin selection in `inputs.js`) so that a flood of tiny custom-asset outputs cannot force an unbounded/oversized `payload.inputs` array. Consider also enforcing a configurable minimum spendable amount per asset, or detecting/skipping dust outputs below a fee-rational threshold regardless of asset type.

### Proof of Concept
1. Off-chain, compute the address of a parameterized AA that will eventually receive/hold asset `X` (`address = chash160(['autonomous agent', {base_aa, params}])`), or target any already-deployed AA known to accept asset `X`.
2. Before (or after) the AA exists, submit ordinary payment units sending, e.g., 5,000 outputs of 1 unit each of asset `X` to that address (well within normal unit/message limits by splitting across many units).
3. Trigger the AA to send/forward its balance of asset `X` (e.g. via a `send-all`/full-balance payment message in its response logic).
4. Observe that `completePaymentPayload()`'s `readStableOutputs` query (no `amount>=` floor, no `LIMIT` for non-base assets) returns all 5,000 dust outputs, `iterateUnspentOutputs` pushes 5,000 inputs into `payload.inputs`, exceeding `MAX_INPUTS_PER_PAYMENT_MESSAGE` and causing the response unit to fail composition/validation, leaving the AA unable to spend its asset `X` balance.

### Citations

**File:** aa_composer.js (L1102-1123)
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
