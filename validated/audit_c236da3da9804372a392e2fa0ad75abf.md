### Title
Grief attack on AA response composition via unbounded, non-dust-filtered asset-output scan in `sendUnit` - ([File: aa_composer.js])

### Summary
`handleTrigger`'s inner `sendUnit`/`completePaymentPayload` logic in `aa_composer.js` composes payment messages for an AA response by querying `readStableOutputs`/`readUnstableOutputsSentByAAs` and feeding every returned row into `iterateUnspentOutputs`, which pushes each row as a payment `input` with no upper bound. Unlike the base-asset case, custom-asset outputs sent to an AA are not filtered by a minimum "dust" amount, and unlike normal user-composed payments, AA-generated payment messages are exempt from the `MAX_INPUTS_PER_PAYMENT_MESSAGE` check in `validation.js`. Any address can flood an AA with a large number of tiny-value custom-asset outputs, causing every subsequent AA response that must spend/forward that asset to attempt to consume all of them at once.

### Finding Description
In `aa_composer.js`, `readStableOutputs` builds the SQL: [1](#0-0) 

Note the dust-protection comment applies only to the base asset: `amount>=FULL_TRANSFER_INPUT_SIZE` is added only when `!asset`. When `asset` is set, the query has no lower bound on `amount` and no `LIMIT` clause, so it returns every unspent output of that asset ever sent to the AA address.

All returned rows are consumed unconditionally: [2](#0-1) 

Each row becomes a separate `input` object pushed into `payload.inputs`, and `arrUsedOutputIds` (used inside `NOT IN(...)`) grows accordingly, feeding a larger literal list back into subsequent SQL queries within the same trigger handling (`readUnstableOutputsSentByAAs` reuses the same growing `arrUsedOutputIds.join(', ')`), compounding cost as the flood grows.

Crucially, `validation.js`'s input-count guard explicitly exempts AA-authored units:
`if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA) return callback("too many inputs");`
so there is no protocol-level cap preventing an AA response from attempting to include an unbounded number of asset inputs collected this way.

This is directly analogous to the reported bug class: an attacker (any unprivileged asset issuer/funder) can create arbitrarily many small legitimate deposits of a custom asset to a target AA address, inflating the set of records that a later, unrelated, legitimate operation (here: AA response composition) must iterate over in full, with no per-call size cap and no minimum-value filter for non-base assets.

### Impact Explanation
Once an AA that forwards/returns a received custom asset (a very common pattern — e.g., swap/AMM/vault-style AAs) accumulates enough tiny dust outputs of that asset, its response composition must include all of them as inputs. This:
- Produces a unit whose message size/inputs grow unbounded, risking rejection by other size constraints elsewhere in composition/validation, so the AA response fails/bounces repeatedly and the AA can never successfully spend/return the underlying (legitimate, valuable) balance in that asset — an AA fund-freezing condition analogous to the reported "tokens blocked inside the bounty contract."
- Even where the response nominally succeeds, computing and re-validating it becomes progressively more expensive for every node re-executing the trigger (deterministic AA execution is replayed by all full nodes), degrading throughput and creating a network-wide processing burden that scales with attacker-controlled deposit count, at negligible cost to the attacker (tiny dust amounts of a self-issued or cheap asset).

This satisfies the "AA fund loss or freezing" / "network unable to confirm new units in a timely, resource-bounded way" impact bars from the validation rules.

### Likelihood Explanation
Likelihood is Medium: exploitation requires (a) identifying/targeting an AA that will attempt to consume/forward a specific custom asset balance and (b) sending many small-value payment units of that asset to the AA address, which is fully permitted unprivileged behavior (any address can pay any amount of any asset to any address, and issuing a custom asset for the purpose costs only network fees for many small units). No special privileges, hub cooperation, or protocol bypass is needed — only ordinary unit posting.

### Recommendation
- Apply the same dust-minimum filtering used for the base asset (`amount>=FULL_TRANSFER_INPUT_SIZE`) to custom-asset outputs in `readStableOutputs`/`readUnstableOutputsSentByAAs`, or introduce an asset-specific minimum consumable amount.
- Add a `LIMIT` to these queries (bounded by `MAX_INPUTS_PER_PAYMENT_MESSAGE` minus reserved slots) so a single response composition can never attempt to gather more inputs than the unit format can support, and gracefully carry over remaining outputs to later responses instead of failing outright.
- Reconsider exempting AA-authored payment messages from `MAX_INPUTS_PER_PAYMENT_MESSAGE` in `validation.js`; if the exemption is required for legitimate use cases, enforce an alternate hard cap specific to AA-composed messages to bound worst-case validation cost.

### Proof of Concept
1. Deploy/target an AA `X` that, upon trigger, sends back or forwards the entirety of its received balance in asset `A` (a common bounce/refund/vault pattern).
2. As an unprivileged attacker, issue a large number (e.g., tens of thousands) of minimal-value (`amount=1`) payment units of asset `A` to `X`'s address across many separate transactions — each individually valid and cheap.
3. Trigger `X` so that it must respond by paying out asset `A`. `handleTrigger` → `sendUnit` → `completePaymentPayload` calls `readStableOutputs` for asset `A`: [3](#0-2) 
   Because there is no `amount>=` filter and no `LIMIT` for the asset branch, all attacker-created dust outputs are returned and consumed via `iterateUnspentOutputs`, producing a payment message with as many inputs as dust outputs exist.
4. Observe that `validation.js`'s `payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` check is bypassed for AA-authored units (`!objValidationState.bAA` guard), so the oversized input set is not rejected by that specific guard, while the AA's genuine asset balance remains effectively unusable/expensive to move as the dust set grows with each additional attacker-submitted unit.

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
