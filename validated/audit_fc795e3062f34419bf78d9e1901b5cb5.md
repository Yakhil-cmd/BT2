### Title
AA custom-asset dust flooding forces unbounded, unbounded-size responses that drain the AA's byte balance - (File: aa_composer.js)

### Summary
`aa_composer.js`'s output-selection logic that composes an AA's payment response explicitly filters out dust outputs to prevent a "spam the AA with tiny outputs" attack, but this protection is applied **only to base-currency (byte) outputs**, not to custom-asset outputs. Combined with the fact that AA-generated units are exempt from the normal `MAX_INPUTS_PER_PAYMENT_MESSAGE` and `MAX_UNIT_LENGTH` checks in `validation.js`, an attacker can flood an AA's address with a very large number of minimal-amount outputs of a custom asset, forcing every future AA response paid in that asset to consume all of them as inputs and bloat the unit size, draining the AA's bytes for fees (or bouncing the trigger) — the same "individually cheap to create, unprofitable/impossible to clean up, and pays out in losses to the counterparty" pattern as the referenced report's small-loan/never-liquidated bug.

### Finding Description
When an AA composes a payment message, `pickPaymentAmountsFn`'s `readStableOutputs`/`readUnstableOutputsSentByAAs` queries select unspent outputs at the AA's address to use as inputs. For the base asset, outputs smaller than `FULL_TRANSFER_INPUT_SIZE` are explicitly excluded, with the comment stating the exact rationale: to prevent a dust attack that spams the AA with tiny outputs so it "spends all its money for fees when it tries to respond": [1](#0-0) 

But this size filter is applied **only when `asset` is falsy** (base/bytes) — `"asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)"` — meaning for any custom asset, no minimum-amount threshold exists at all: [2](#0-1) [3](#0-2) 

Normally, non-AA units are protected from unbounded input/size growth by hard caps in validation: `payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE` and `headers_commission + payload_commission > constants.MAX_UNIT_LENGTH`. Both checks are explicitly **bypassed for AA-authored units** (`!objValidationState.bAA`, `!bAA`): [4](#0-3) [5](#0-4) 

So an unprivileged attacker can:
1. Issue/hold a transferable custom asset, and send a single unit with up to `MAX_OUTPUTS_PER_PAYMENT_MESSAGE` outputs of that asset to the target AA's address, each carrying the smallest possible positive amount (dust). This can be repeated across many units cheaply, since output creation cost is a normal, small payment fee unrelated to the AA's eventual liability.
2. Later, whenever a legitimate user triggers the AA and the AA needs to pay out that asset (e.g., a swap/DEX/vault-style AA holding user balances), `completePaymentPayload`/`pickPaymentAmountsFn` will pull in these dust outputs one-by-one (`iterateUnspentOutputs`) because they aren't filtered out, and — because there is no `MAX_INPUTS_PER_PAYMENT_MESSAGE` cap for AA units — it can be forced to include an enormous number of inputs to accumulate the payout amount.
3. The resulting unit's real serialized size (computed later via `objectLength.getTotalPayloadSize`) grows proportionally with the number of dust inputs, inflating `headers_commission`/`payload_commission`, which is paid in bytes out of the AA's own balance. Because `MAX_UNIT_LENGTH` is not enforced for AA units, this growth is effectively unbounded, letting an attacker force each AA response into disproportionately large byte fees or an outright bounce (undoing the trigger and consuming the AA's or trigger sender's bytes), unlike a normal wallet payment where the sender's own coin selection would simply avoid dust and stay under `MAX_INPUTS_PER_PAYMENT_MESSAGE`.

### Impact Explanation
This directly parallels the referenced report's core issue: an attacker can cheaply create a large number of "small positions" (dust asset outputs) that are individually worthless but must eventually be consumed/settled by the victim (the AA acting as lender/custodian), and doing so imposes a disproportionate cost. Here the cost is paid in real bytes drained from the AA's balance (fund loss for the AA and its legitimate stakeholders) or causes trigger responses to fail/bounce (AA unable to service legitimate withdrawals — a freezing/DoS of AA funds). Any AA that holds and pays out a custom, freely transferable asset to user-controlled addresses is exposed, which is a broad class of DeFi-style AAs (DEXes, vaults, lending/staking AAs) built on top of ocore.

### Likelihood Explanation
Sending assets to an arbitrary address including an AA's address requires no special privilege — a normal `payment` message with a transferable asset is sufficient, and `MAX_OUTPUTS_PER_PAYMENT_MESSAGE` outputs can be created per unit, so flooding thousands of dust outputs is inexpensive and requires only a handful of transactions. The only prerequisite is that the target AA actually holds/pays out a transferable custom asset to addresses the attacker also controls or can direct funds to, which is common for AA-based token/DEX/vault designs.

### Recommendation
Apply the same minimum-output-size dust filter used for the base asset to custom-asset outputs when selecting AA inputs in `readStableOutputs`/`readUnstableOutputsSentByAAs` (e.g., ignore asset outputs whose amount is not worth the marginal input-size cost, similar in spirit to `FULL_TRANSFER_INPUT_SIZE`). Additionally, consider re-enabling a hard cap on the number of inputs (`MAX_INPUTS_PER_PAYMENT_MESSAGE`) and overall unit size for AA-authored units, or split large responses into multiple AA-issued units rather than exempting them entirely from these checks in `validation.js`.

### Proof of Concept
1. Attacker issues/owns transferable custom asset `X`.
2. Attacker sends unit(s) to `AA_address` containing up to `MAX_OUTPUTS_PER_PAYMENT_MESSAGE` payment outputs of asset `X`, each with the smallest positive amount, repeated across several units to accumulate thousands of dust outputs at `AA_address`.
3. A legitimate user triggers the AA in a way that requires it to pay out asset `X` (e.g., withdraw balance, swap output).
4. Inside `handleTrigger` → `pickPaymentAmountsFn` → `readStableOutputs`/`iterateUnspentOutputs`, because the size filter `amount>=FULL_TRANSFER_INPUT_SIZE` is skipped for non-base assets, all dust outputs are eligible and get pulled in as inputs one at a time until the target payout amount is reached (`aa_composer.js` lines 1140-1173, 1102-1138).
5. Because `validation.js` skips the `MAX_INPUTS_PER_PAYMENT_MESSAGE` and `MAX_UNIT_LENGTH` checks for AA units (`validation.js` lines 2137-2140, 267-268), the composed unit can grow arbitrarily large, causing outsized `headers_commission`/`payload_commission` charged against the AA's byte balance, or an outright failure/bounce of the response when the AA cannot cover the inflated fee.

### Citations

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

**File:** aa_composer.js (L1161-1173)
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
			}
```

**File:** validation.js (L267-268)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```

**File:** validation.js (L2137-2140)
```javascript
	if (payload.inputs.length > constants.MAX_INPUTS_PER_PAYMENT_MESSAGE && !objValidationState.bAA)
		return callback("too many inputs");
	if (payload.outputs.length > constants.MAX_OUTPUTS_PER_PAYMENT_MESSAGE && !storage.isGenesisUnit(objUnit.unit))
		return callback("too many outputs");
```
