## Title
AA can still spend its own auto-destroyed asset balance before the `pemCurvesFixMci` upgrade, reviving supply that should be permanently burned - ([File: aa_composer.js])

## Summary
An `auto_destroy` asset is designed so that once a divisible token is sent back to its definer address, that balance is permanently removed from circulation (burned) and can never be spent again — this is the mechanism used by AA-issued capped tokens to guarantee that the circulating supply never exceeds `cap`. In `aa_composer.js`'s own unspent-output selection logic, the exclusion of the definer's auto-destroyed balance is explicitly gated behind an MCI version check, meaning the protection did not always exist.

## Finding Description
When an AA composes a payment message for an asset it manages, it selects spendable outputs via `readStableOutputs` / `readUnstableOutputsSentByAAs` inside `sendUnit()`: [1](#0-0) [2](#0-1) 

Both functions contain the guard:
```
if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
    return handleRows([]);
```
This means the AA's own auto-destroyed balance is excluded from being picked as spendable **only when `mci >= constants.pemCurvesFixMci`**. Below that MCI, the query proceeds normally and would return the outputs sitting at the definer (AA) address for an `auto_destroy` asset — i.e., balances that were sent back to the issuer specifically to be destroyed. This is consistent with the general validation-layer semantics for `auto_destroy`, where any output sent to the definer address is treated as destroyed and can never again be a valid *transfer* input owned by the definer: [3](#0-2)  explicitly rejects using such an output as a transfer input, and the payload-balance rule in `validatePaymentInputsAndOutputs` treats "payment to the definer" as one of the only allowed non-transferrable flows: [4](#0-3) .

However, the AA composer's own bookkeeping (which decides which unspent outputs to reference as *new issue-avoiding* inputs before validation ever runs) did not always honor that semantic — before the version gate was introduced, the AA could pick up its own destroyed balance and re-include it as an ordinary `transfer` input in a new payment, re-injecting previously "burned" supply back into circulation.

## Impact Explanation
If exploitable in the affected version range, this breaks the fundamental economic guarantee of a capped, `auto_destroy` asset: tokens that were sent to the definer specifically to reduce circulating supply (e.g., a burn/redeem mechanism in an AA-based stablecoin or bonding-curve contract) could be silently reintroduced into circulation by the AA itself, inflating the effective supply beyond what holders and integrators expect — a direct analog to Bitfinex/Crypto Capital's undisclosed use and re-injection of client funds that were supposed to be immobilized, causing systemic loss of trust in the represented backing of the asset. In ocore terms this maps to the allowed impact categories of "asset issuance/transfer conditions" and "supply inflation."

## Likelihood Explanation
The condition is entirely governed by `mci >= constants.pemCurvesFixMci`, a hard-fork/network-upgrade constant. I was unable to fully confirm from the available index whether `pemCurvesFixMci` has already activated on production mainnet at present (the constant is referenced across `constants.js`, `formula/validation.js`, `formula/evaluation.js`, `main_chain.js`, `storage.js`, `definition.js`, `signed_message.js`, `signature.js`, `composer.js` — suggesting it is an already-passed protocol upgrade bundling multiple fixes, in which case this issue is **already patched** for all current units). This is an important caveat: if `pemCurvesFixMci` is already in the past relative to the current main_chain_index, this specific behavior is not currently exploitable, and the finding is historical rather than live. I could not verify the exact current MCI vs. the constant's value from the indexed code alone.

## Recommendation
- Confirm the exact value of `constants.pemCurvesFixMci` and the current network MCI to determine whether this gate has already activated on all networks (mainnet/testnet/devnet) used by this deployment.
- If any network instance (e.g., a private/devnet deployment based on this fork) has not yet crossed `pemCurvesFixMci`, treat any `auto_destroy` capped asset issued by an AA as **at risk** of supply reinflation and consider back-porting the exclusion unconditionally (remove the MCI gate) rather than tying a core economic invariant to a network-wide upgrade point.
- Add a regression test that specifically checks an AA cannot spend its own auto-destroyed balance regardless of the current MCI, to prevent future regressions of this invariant.

## Proof of Concept
Conceptual reproduction (requires a network state with `mci < constants.pemCurvesFixMci`):
1. AA definer address `A` defines a capped, `auto_destroy`, `issued_by_definer_only` divisible asset `X` (per `validateAssetDefinition`, capped assets must be `issued_by_definer_only`: [5](#0-4) ).
2. A trigger sends units of `X` back to AA address `A` (a legitimate "redeem/burn" flow), which is accepted per [4](#0-3)  since output-to-definer is allowed even though the asset is non-transferrable.
3. On a subsequent trigger requiring the AA to pay out asset `X`, `sendUnit()` calls `readStableOutputs`/`readUnstableOutputsSentByAAs`, which — at `mci < constants.pemCurvesFixMci` — do not exclude `A`'s own balance of the `auto_destroy` asset, allowing those "burned" outputs to be selected as ordinary transfer inputs in the new payment (see cited lines 1140-1173 of `aa_composer.js`).
4. The resulting payment message re-spends coins that should have been permanently destroyed, increasing the effective circulating supply beyond what redemptions should have permitted.

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

**File:** validation.js (L2504-2505)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
```

**File:** validation.js (L2616-2629)
```javascript
				if (!objAsset.is_transferrable){ // the condition holds for issues too
					if (arrInputAddresses.length === 1 && arrInputAddresses[0] === objAsset.definer_address
					   || arrOutputAddresses.length === 1 && arrOutputAddresses[0] === objAsset.definer_address
						// sending payment to the definer and the change back to oneself
					   || !(objAsset.fixed_denominations && objAsset.is_private) 
							&& arrInputAddresses.length === 1 && arrOutputAddresses.length === 2 
							&& arrOutputAddresses.indexOf(objAsset.definer_address) >= 0
							&& arrOutputAddresses.indexOf(arrInputAddresses[0]) >= 0
					   ){
						// good
					}
					else
						return callback("the asset is not transferrable");
				}
```

**File:** validation.js (L2802-2803)
```javascript
	if (payload.cap && !payload.issued_by_definer_only)
		return callback("if capped, must be issued by definer only");
```
