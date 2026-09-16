This is the key finding — in `aa_composer.js`, `completePaymentPayload`'s `iterateUnspentOutputs`/`readStableOutputs` picks up **every unspent output** owned by the AA address one at a time, and it is not capped by `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` the way a normal user-composed payment is (that cap is explicitly bypassed for AAs in `validatePaymentInputsAndOutputs`). This directly parallels the `getLockedFunds`/`deposits` DOS: an attacker can cheaply grow the AA's set of spendable outputs for one address, and the very operation meant to pay out (its normal response/withdrawal payment) is the one that must iterate over that unboundedly-grown collection, causing that AA's future responses to fail/bounce and the associated triggering user's funds to be frozen.

### Title
AA payment-input coin selection iterates all address UTXOs with no cap, enabling dust-flooding DOS that freezes AA responses - (File: aa_composer.js)

### Summary
`completePaymentPayload()` / `iterateUnspentOutputs()` in `aa_composer.js` builds the `payload.inputs` array of an AA's outgoing payment by walking through **all** unspent outputs (`readStableOutputs`, `readUnstableOutputsSentByAAs`) owned by the AA address, in ascending `main_chain_index, unit, output_index` order, adding one input per unspent output until the target amount is reached. This mirrors `BountyCore.getLockedFunds()`'s unbounded loop over `deposits`, except here the growable, attacker-fed collection is the AA address's own UTXO set.

### Finding Description
Any address (including AAs) can be sent bytes/asset outputs by anyone, and each such transfer creates one more row in `outputs` for that address. `readStableOutputs` in `aa_composer.js` explicitly tries to mitigate dust by ignoring base-asset outputs `< FULL_TRANSFER_INPUT_SIZE`: [1](#0-0) 
but this floor is only ~net-neutral-fee-sized — it does not bound the *number* of such outputs an attacker can create, only their individual minimum size. An attacker can send thousands of outputs each just above that floor to the AA's address at negligible aggregate cost.

The coin-selection loop then adds these outputs to `payload.inputs` one at a time inside `iterateUnspentOutputs`: [2](#0-1) 
There is no cap analogous to `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` applied while building this list, and critically the unit-validation-time check that normally limits the number of payment inputs is explicitly bypassed for AA-generated units: [3](#0-2) 
So while a regular user's payment is capped, an AA's own outgoing payment is not, and it is exactly the AA's own historical inbox of outputs (freely grown by any depositor) that determines how many inputs it needs.

As the AA accumulates many small unspent outputs from repeated cheap deposits, any response that needs to pay out an amount comparable to (or larger than) many small deposits will have to consume progressively more inputs. Because `net_target_amount`/`size` grow with every input added (`FULL_TRANSFER_INPUT_SIZE` per input, line 1111-1113), the response unit's payload size, oversize fee, and header/payload commissions grow correspondingly, and the number of `INSERT INTO parenthoods/inputs` operations and `checkInputDoubleSpend`/`objValidationState.arrInputKeys.indexOf` lookups performed during subsequent validation (validation.js lines 2402-2405, 2500-2510) scale with the same unbounded count, since `arrInputKeys`/`arrInputAddresses` lookups are O(n) per input, making the whole check O(n²) for that unit. Eventually the generated response unit can become too large (hitting protocol/unit size limits or unreasonably large fees consuming the AA's balance), or validation of that response can become prohibitively expensive, causing `handleTrigger`'s `sendUnit`/`validateAndSaveUnit` to fail and the AA to `bounce()` the trigger.

### Impact Explanation
This is analogous to "refundDeposit can be DOS": a single unprivileged party (anyone able to send outputs to the AA's address, which is inherent to interacting with any AA) can grow an internal collection that a core AA payout function must fully scan/consume, without any bound matching the general anti-spam bound used elsewhere in the protocol (`MAX_INPUTS_PER_PAYMENT_MESSAGE` is explicitly skipped for AAs). The result can be an AA whose future payout responses become unreliable (excess fees eating into user deposits, oversized/failed response units, or bounced triggers), which is a form of AA fund loss/freezing for legitimate users triggering that AA.

### Likelihood Explanation
Likelihood is moderate: sending many small outputs to an AA address is cheap (bounded only by the `FULL_TRANSFER_INPUT_SIZE` dust floor and normal unit fees), and any AA holding/forwarding bytes or an asset for its users is a plausible, common target. It requires the AA to actually need to spend an amount that forces consumption of many small inputs (i.e., the attack is more effective against AAs whose balance composition an attacker can influence by depositing dust), so the practical severity depends on the specific AA's payout logic, but the underlying engine-level gap (no input cap for AA payments, coupled with O(n) key-lookup validation) is a genuine, reachable weakness in `ocore` itself, independent of any particular AA script.

### Recommendation
- Apply an upper bound on the number of inputs `completePaymentPayload`/`iterateUnspentOutputs` will accumulate for a single AA response payment (e.g., enforce `constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` for AA payments too, or consolidate dust via periodic self-sweeps), rather than exempting AAs from the check at `validation.js:2137`.
- Consider raising the dust floor for AA-received outputs and/or actively consolidating small outputs owned by an AA address during idle periods so an attacker cannot cheaply inflate the UTXO count that a payout must draw from.
- Replace the O(n) `arrInputKeys.indexOf`/`arrInputAddresses.indexOf` linear scans in `validatePaymentInputsAndOutputs` with a Set/hashmap to avoid quadratic blow-up even if large input counts occur.

### Proof of Concept
1. Deploy/target an existing AA (address `A`) that, on some trigger, pays out bytes/an asset to the triggering user based on accumulated balance (a common pattern, e.g. bank/exchange AAs).
2. Attacker repeatedly sends many small payments (each just above `FULL_TRANSFER_INPUT_SIZE`) to `A`'s address from many throwaway addresses over time — cheap because the base network fee per unit is minimal and this requires no privileged access.
3. Trigger the AA to make a legitimate payout of an amount that must be composed from many of the small deposited outputs.
4. Observe in `aa_composer.js`'s `completePaymentPayload`/`iterateUnspentOutputs` that the number of `payload.inputs` grows with the number of dust outputs the attacker deposited, increasing `size`/`net_target_amount`/oversize fee at each step (lines 1102-1123), and that `validatePaymentInputsAndOutputs` performs an O(n) `arrInputKeys.indexOf` check per input while never rejecting for "too many inputs" because of the AA exemption at `validation.js:2137-2138`.
5. With enough accumulated dust, the resulting response unit either fails oversize/fee constraints or takes disproportionately long/expensive to build and validate, causing the AA to bounce the trigger and the requesting user's funds sent with the trigger to be frozen/returned minus fees rather than processed.

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

**File:** aa_composer.js (L1144-1155)
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
			}
```

**File:** validation.js (L2137-2138)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
```
