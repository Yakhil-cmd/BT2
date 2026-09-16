### Title
Anti-dust-DDoS protection for AA outputs applies only to base-currency payments, leaving non-base assets fully exposed - ([File: aa_composer.js])

### Summary
When an AA composes a response unit, it selects unspent outputs sent to its own address to fund the response. The code explicitly filters out dust outputs to prevent a spam/DDoS attack, but this filter is applied **only** to the base asset. Outputs denominated in any custom (non-base) asset are read and consumed with no minimum-amount filter at all, so the anti-dust protection that Kairos-style analysis flags as inconsistent (protected currency vs. unprotected currency) exists here in the same asymmetric form.

### Finding Description
In `readStableOutputs` and `readUnstableOutputsSentByAAs` inside `sendUnit`/`completePaymentPayload` in `aa_composer.js`, the query that selects spendable outputs for a given `asset` is: [1](#0-0) [2](#0-1) 

The comment on the base-asset branch states the intent directly: "byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond." This threshold is implemented via `amount>=" + FULL_TRANSFER_INPUT_SIZE` but that clause is only appended when `asset` is falsy (i.e., the base currency). When `asset` is truthy (any custom/non-base asset), the `WHERE` clause becomes simply `asset="+conn.escape(asset)` with **no lower bound on `amount`** — any output, no matter how small, is read, marked spent, and consumed as an input.

Because asset issuance in this system is permissionless (anyone can define a new asset and pay it to any address, including an AA address, via a normal `payment` message), an attacker can:
1. Issue a new asset.
2. Send an unbounded number of dust outputs of that asset to a target AA's address.
3. Force the AA, on every subsequent trigger that causes it to compute/send a balance in that asset (e.g., a `send-all` output, balance tracking `state` vars, or any payment message referencing that asset), to enumerate and consume all of those dust UTXOs as inputs when composing its response unit.

This mirrors the reported bug class exactly: protection is selectively enabled for one "listed" currency (base bytes, analogous to admin-configured ERC20s) while non-listed/custom assets get zero protection, even though the underlying platform is explicitly designed to be permissionless about which assets can interact with contracts/AAs.

### Impact Explanation
An attacker can bloat an AA's set of spendable outputs in an arbitrary custom asset with unlimited dust, without paying any meaningfully deterring cost beyond ordinary issuance/transfer fees (which are cheap and unrelated to the dust amount). When the AA is triggered by a legitimate user and needs to pay out or track that asset's balance, `sendUnit`'s input-gathering loop must pull in every one of these dust outputs, inflating `unit` size and the number of inputs in the payment message. This directly increases the oversize fee (`getOversizeFee`) and total transaction size the AA must cover from its own balance — potentially exhausting the AA's balance/bounce fees on subsequent triggers, i.e., causing the AA to be unable to answer legitimate requests (bounce due to insufficient fees) or to lose funds paying oversize/storage fees driven entirely by attacker-controlled dust. This is a fund-freezing/fund-loss DoS against any AA that deals with non-base assets, which is a core, expected use case (all token/DEX/AA contracts on custom assets).

### Likelihood Explanation
Any unprivileged user can trigger this: asset issuance and payments to any address (including AA addresses) require no special permission, no admin allow-listing, and are core primitives of the protocol (`payment` messages, `asset` definitions). The bug requires no cooperation from the AA owner and no race conditions — it is a straightforward repeated issuance/payment of dust amounts of a chosen asset to a target AA address, an action any single poster can perform independently at will.

### Recommendation
Apply the same (or an equivalent, asset-aware) minimum-amount filter used for base outputs to non-base assets as well, e.g., derive a per-asset minimum output threshold (based on typical input/commission overhead for that asset, or a configurable/derived value similar to `FULL_TRANSFER_INPUT_SIZE`) and add it to the `WHERE` clause in both `readStableOutputs` and `readUnstableOutputsSentByAAs` when `asset` is set, instead of omitting any amount condition in that branch.

### Proof of Concept
1. Deploy/define an AA that accepts a custom asset and, on trigger, does a `send-all` payment of that asset back to `trigger.address` (a common pattern, e.g., wrappers/exchanges).
2. Attacker issues asset `X` and sends thousands of 1-unit outputs of asset `X` to the AA's address over many units — each accepted with no dust filtering since the `asset` branch of the query in `aa_composer.js` (lines 1149/1167) has no `amount>=` condition.
3. A legitimate user later triggers the AA with a real deposit of asset `X`; when the AA composes its send-all response, `iterateUnspentOutputs`/`readStableOutputs` pulls in all the attacker's dust outputs as inputs (no filter excludes them), inflating the unit size and oversize fee charged against the AA's base-currency balance, and potentially causing the response to bounce for insufficient fees or drain the AA's reserves — reproducing the exact "DDoS via minimal-protection non-listed currency" pattern from the referenced report.

### Citations

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

**File:** aa_composer.js (L1157-1173)
```javascript
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
