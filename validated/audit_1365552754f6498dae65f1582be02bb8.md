### Title
AA payment messages for fixed-denomination (indivisible) assets are silently dropped, causing value leak on proportional withdrawals - (File: aa_composer.js)

### Summary
`handleTrigger()`'s response-composer in `aa_composer.js` silently filters out any `payment` message whose `asset` has `fixed_denominations: true`, instead of bouncing the whole trigger. An AA that computes and tries to pay out a proportional share of such an asset (e.g. a fair-share/exit/vault-style AA, analogous to `rageQuit()`) will have that specific payment message dropped while the rest of the response (state updates, other payments, trigger.data acceptance) still commits, causing the user to permanently lose the fixed-denomination-asset share they were owed.

### Finding Description
In `aa_composer.js`, `handleTrigger()` iterates over AA response messages and, for `payment` messages carrying a non-base asset, loads the asset definition: [1](#0-0) 

If the asset is `fixed_denominations` (i.e. an indivisible asset, ocore's structural equivalent of a non-fungible/denominated ERC1155-style token), the message is simply skipped with the comment `// will skip it later`, without any error. Later, after all other messages have been processed, the composer performs a second filtering pass that unconditionally removes every payment message referencing a `fixed_denominations` asset: [2](#0-1) 

If this filtering empties the whole message list, the AA falls through to `handleSuccessfulEmptyResponseUnit(null)` — i.e., the trigger unit is still treated as *successfully* processed (not bounced), even though the intended payment never happened. If other messages remain (e.g., a `state` update or a base-asset payment), those still execute normally while only the fixed-denomination payment silently vanishes.

This is structurally the same bug class as the C4 finding: a function that computes a user's fair/proportional share of an asset and attempts to transfer it, but the transfer mechanism does not support that particular asset "shape" (ERC1155 vs. ocore's indivisible/fixed-denomination asset), so the value is not delivered even though the surrounding accounting (e.g. `var[...]` state, trigger acceptance, `response`) assumes it was.

Indivisible/fixed-denomination assets are explicitly a first-class, AA-reachable asset type: an AA can define such an asset via an `asset` message (`fixed_denominations: true`, with `denominations`), as validated in `validation.js` and `aa_validation.js`: [3](#0-2) [4](#0-3) 

and it can receive/hold such assets as trigger outputs (any unprivileged trigger sender can send a fixed-denomination asset to the AA as part of `trigger.output`). The AA's oscript formulas can read `balance[asset]` and `trigger.output[[asset=...]]` for such assets and compute a proportional payout — but any attempt to actually pay it back via a `payment` message is unconditionally dropped by the composer, regardless of the formula's intent.

### Impact Explanation
Any AA that is designed to hold and redistribute an indivisible/fixed-denomination asset (a common pattern for representing whole/non-fungible-like units, similar to how the reported bug affects ERC1155 fungible tokens held by a Party contract) will silently fail to deliver that portion of funds to the rightful recipient on any trigger that includes such a payout message. Because:
- the trigger unit is not bounced (funds/state already committed for the rest of the response),
- the AA's internal state (`var[...]`) may already reflect the share as "distributed" or "consumed" (e.g., balances decremented, `mm_asset_outstanding` reduced) even though the actual transfer never went out,

the asset held by the AA is permanently stuck/lost from the perspective of the user who was owed it, meeting the "AA fund loss" bar for this scan (Medium severity, matching the original finding's cccz-judged Medium/value-leak criteria).

### Likelihood Explanation
High likelihood of being hit whenever an AA author defines a `fixed_denominations` asset and writes formulas that pay it back to users (a natural and encouraged pattern — AAs are explicitly allowed to define and receive such assets). No special privilege is needed: any unprivileged AA trigger sender can send such an asset into the AA, and any AA author (also unprivileged, permissionless) can write the (seemingly correct) oscript that tries to pay it back out — the bug is in the AA execution engine (`aa_composer.js`) silently discarding those payment messages, not in the AA author's code.

### Recommendation
- In `aa_composer.js`, when a `payment` message references a `fixed_denominations` asset, do not silently drop it. Either:
  - Bounce the whole trigger with an explicit error ("cannot send fixed-denomination asset from AA"), so the AA author is forced to avoid attempting the payout and the trigger's funds/state changes are rolled back consistently; or
  - Implement proper indivisible-asset composition support (mirroring `indivisible_asset.js`'s coin-picking logic) so that AAs actually can pay out fixed-denomination assets.
- At minimum, ensure `aa_validation.js` rejects AA definitions whose payment messages reference (or could reference, via formulas) `fixed_denominations` assets, so this failure mode is caught at AA-definition time rather than silently at execution time.

### Proof of Concept
1. An AA author defines an asset with `fixed_denominations: true` (e.g., in the AA's own `asset` message, permitted per `aa_validation.js` lines 225-229) and writes trigger-handling logic that:
   - receives the fixed-denomination asset from a user (`trigger.output[[asset=$fd_asset]]`),
   - updates internal accounting (`var['balance_'||trigger.address] += ...`),
   - and, on a later "withdraw" trigger, tries to pay the user's proportional share back via a `payment` message with `asset: $fd_asset`.
2. A user sends the "withdraw" trigger. `handleTrigger()` processes the messages: the `payment` message for `$fd_asset` is loaded via `storage.loadAssetWithListOfAttestedAuthors`, and because `objAsset.fixed_denominations` is true, it is queued to be skipped (`aa_composer.js:1327-1328`).
3. In the final filtering pass (`aa_composer.js:1356`), the payment message is removed. If it was the only message, `handleSuccessfulEmptyResponseUnit(null)` is invoked — the trigger unit is accepted as successful even though the user receives nothing back.
4. Any accompanying `state` message that already decremented the AA's internal record of the user's balance still commits, since the state message doesn't reference the dropped asset itself and is not filtered — permanently losing the user's claim to the fixed-denomination asset held by the AA.

### Citations

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_composer.js (L1350-1361)
```javascript
				messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
				if (messages.length === 0) {
					error_message = 'no messages after removing 0-outputs (2nd pass)';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
				messages = messages.filter(function (message) { return (message.app !== 'payment' || !message.payload.asset || !assetInfos[message.payload.asset].fixed_denominations); });
				if (messages.length === 0) {
					error_message = 'no messages after removing fixed denominations';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```

**File:** aa_validation.js (L225-229)
```javascript
				case 'asset':
					if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations", "init"]))
						return cb2("unknown fields in asset definition in AA");
					if (payload.fixed_denominations === true && !isNonemptyArray(payload.denominations))
						return cb2("denominations not defined");
```

**File:** validation.js (L2089-2096)
```javascript
		if (objAsset.fixed_denominations){
			if (!isPositiveInteger(payload.denomination))
				return callback("no denomination");
		}
		else{
			if ("denomination" in payload)
				return callback("denomination in arbitrary-amounts asset")
		}
```
