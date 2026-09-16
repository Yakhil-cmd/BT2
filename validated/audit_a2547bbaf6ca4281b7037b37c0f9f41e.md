## Analog Finding

### Title
Byte outputs below 60 bytes sent to an AA address are permanently unspendable, causing AA fund freezing - (File: `aa_composer.js`)

### Summary
The external report describes a class of bug where a protocol enforces a minimum size for *withdrawing* funds (`enqueue()` requiring ≥0.05 ETH) while imposing no corresponding minimum on *depositing* funds (`deposit()` accepts any amount), and the path to top up the balance can be independently blocked (private pool, pause), leaving the user's stake permanently unrecoverable. The reachable analog in `ocore` is the AA response-composition logic in `aa_composer.js`, where any address can send an arbitrary, unrestricted amount of bytes to an AA (no minimum), but the AA's own payment-composition logic can only ever spend a *received* base-asset output if it is at least `FULL_TRANSFER_INPUT_SIZE` (60 bytes) in size. Any output below that threshold that is sent to an AA can never be selected as an input by the AA itself, and is therefore permanently frozen inside the AA, with no mechanism to release it.

### Finding Description
When an AA composes its response payment in `sendUnit()` → `completePaymentPayload()`, spendable inputs are selected from two queries, `readStableOutputs()` and `readUnstableOutputsSentByAAs()`: [1](#0-0) 

Both queries filter base-asset outputs with `amount>=FULL_TRANSFER_INPUT_SIZE`, explicitly noting the intent to prevent a dust-spam attack: [2](#0-1) 

`TRANSFER_INPUT_SIZE` is defined as 60 bytes (44+8+8), which is used as the practical dust threshold: [3](#0-2) 

There is, however, no corresponding *minimum* enforced on the receiving side: any unprivileged unit author can send a base-asset output of any size — including 1, 10, or 50 bytes — directly to an AA's address, either as a standalone trigger output or as an incidental additional output in a larger unit. Because the AA's oscript logic can credit such an amount into a state variable (as in the sample bank AA pattern, which unconditionally adds `trigger.output[[asset=base]]` to a balance variable) without any minimum-size gate: [4](#0-3) 

the AA can end up believing it owes/holds an amount that is physically composed of one or more outputs each below the 60-byte spendability threshold. When the AA (or the depositor) later tries to have the AA pay out exactly that amount, `completePaymentPayload()` will never be able to select that specific output as an input — it is excluded by both `readStableOutputs()` and `readUnstableOutputsSentByAAs()` regardless of how much time passes, how many further triggers are sent, or what the AA's total accounted balance is. The bytes remain on-chain as an unspent output forever, permanently frozen from the AA's own spending capability, exactly mirroring the deposit/withdraw threshold mismatch described in the external report (unrestricted "deposit" path, restricted "withdraw" path, no way to reconcile the difference once the funds are already committed).

### Impact Explanation
This is a reachable, unprivileged-triggerable AA fund-freezing bug: any unit poster can send tiny (<60-byte) base-asset outputs to any AA address. Those specific outputs become permanently unspendable by the AA logic (`sendUnit`/`completePaymentPayload`), i.e., bytes are locked and cannot ever be paid out again through the AA's own payment composition, satisfying the "AA fund loss or freezing" impact criterion. An attacker or even an unaware normal user (e.g. sending dust as part of normal interaction, or a bounced/partial response that leaves dust change) can cause bytes to become irrecoverably stuck at the AA address, degrading correctness of AA-managed balances (state vars can promise funds that can never actually be transferred out).

### Likelihood Explanation
Likelihood is high for accidental occurrence: any deposit/vault-style AA that credits `trigger.output[[asset=base]]` (a very common oscript pattern, as shown in the shipped sample AAs) is exposed whenever a user sends less than 60 bytes, or when accumulated dust changes fall under this threshold over multiple interactions. It is also trivially triggerable intentionally by any address without special privileges — no whitelist, ownership, or governance action is required, unlike the acknowledged-but-unmitigated pattern in the external report.

### Recommendation
Enforce a minimum-size requirement on base-asset outputs that are directed to AA addresses at unit-validation time (analogous to Solution 1 in the referenced report — reject deposits below the spendable/dust threshold) so that an AA can never receive an output it can subsequently never spend. Alternatively, remove or lower the `FULL_TRANSFER_INPUT_SIZE` floor used when selecting inputs in `readStableOutputs`/`readUnstableOutputsSentByAAs` (analogous to Solution 2 — allow the AA to consolidate and spend sub-threshold outputs, e.g., by aggregating multiple dust outputs together with a larger output in the same payment message so the net "outputs minus fees" stays non-negative).

### Proof of Concept
1. Deploy an AA using a pattern such as `test/samples/a_bank_without_percent.oscript`, which credits `var[$base_key] = var[$base_key] + trigger.output[[asset=base]]` for every non-withdrawal trigger.
2. Send a unit whose payment message to the AA has a base-asset output of, say, 30 bytes (below `FULL_TRANSFER_INPUT_SIZE` = 60). The oscript credits the sender's balance variable by 30.
3. Later send a withdrawal trigger asking to withdraw exactly that credited amount.
4. In `sendUnit()` → `completePaymentPayload()` → `readStableOutputs()`/`readUnstableOutputsSentByAAs()` in `aa_composer.js` (lines 1140-1173), the 30-byte output is excluded by the `amount>=FULL_TRANSFER_INPUT_SIZE` filter and can never be picked as an input, even though the AA's internal state var says the funds are owed; if no other larger output exists to cover the withdrawal, the response bounces with "not enough funds," and the original 30-byte output remains forever unspent and unspendable by the AA.

### Citations

**File:** aa_composer.js (L37-44)
```javascript
var TRANSFER_INPUT_SIZE = 0 // type: "transfer" omitted
	+ 44 // unit
	+ 8 // message_index
	+ 8; // output_index
var TRANSFER_INPUT_KEYS_SIZE = "unit".length + "message_index".length + "output_index".length;

var OUTPUT_SIZE = 32 + 8; // address + amount
var OUTPUT_KEYS_SIZE = "address".length + "amount".length;
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

**File:** test/samples/a_bank_without_percent.oscript (L31-52)
```text
			{ // silently accept coins
				if: "{!trigger.data.withdraw}",
				messages: [{
					app: 'state',
					state: `{
						$asset = trigger.output[[asset!=base]].asset;
						if ($asset == 'ambiguous')
							bounce('ambiguous asset');
						if (trigger.output[[asset=base]] > 10000){
							$base_key = 'balance_'||trigger.address||'_'||'base';
							var[$base_key] = var[$base_key] + trigger.output[[asset=base]];
							$response_base = trigger.output[[asset=base]] || ' bytes\n';
						}
						if ($asset != 'none'){
							$asset_key = 'balance_'||trigger.address||'_'||$asset;
							var[$asset_key] = var[$asset_key] + trigger.output[[asset=$asset]];
							$response_asset = trigger.output[[asset=$asset]] || ' of ' || $asset || '\n';
						}
						response['message'] = 'accepted coins:\n' || ($response_base otherwise '') || ($response_asset otherwise '');
					}`
				}]
			},
```
