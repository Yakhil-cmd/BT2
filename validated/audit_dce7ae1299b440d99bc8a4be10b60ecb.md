### Title
AA payment messages for fixed-denomination (indivisible) assets are silently dropped without a bounce, permanently freezing reward tokens intended for output - ([File: aa_composer.js])

### Summary
`RecipeOrderbook.sol#L476` assumed the reward token always behaves like a standard ERC20 and made no distinction for “points program” tokens, so upfront‑reward orders that used a points token could never be filled — a required transfer silently reverted the whole intent. In `ocore`'s Autonomous Agent execution engine, `aa_composer.js`'s `sendUnit()` has an analogous “assume‑one‑token‑model” gap: when an AA's oscript emits a `payment` message for an asset that turns out to be `fixed_denominations` (an indivisible/coin-denominated asset — the ocore equivalent of a token type that doesn't fit the “plain divisible balance” model, much like the points contract doesn't fit the plain ERC20 model), the message is not rejected/bounced but is silently filtered out of the outgoing unit, while the AA's state-update formula (which already ran and may have decremented internal bookkeeping) is not rolled back accordingly.

### Finding Description
When an AA constructs its response messages, each non-base payment message is checked against the loaded asset info: [1](#0-0) 

If `objAsset.fixed_denominations` is true, the code simply calls `cb()` without completing the payload — it does **not** bounce nor raise an error, only a comment says "will skip it later". Two passes later, these indivisible-asset payment messages are unconditionally stripped from the outgoing unit: [2](#0-1) 

If, after this filtering, no messages remain, the AA silently finishes with `handleSuccessfulEmptyResponseUnit(null)` — i.e., the trigger is treated as fully and successfully processed, the AA's `state` (`stateVars`) mutations from `executeStateUpdateFormula`/`evaluateAA` are committed, and the associated balance in `aa_balances` is left untouched for that asset (since no output was ever produced and `updateFinalAABalances` never executes for a dropped message) — but the AA's own bytecode logic never learns that its intended payment did not go out.

This mirrors the Cantina finding precisely: the code path assumes a single, uniform "transferable divisible token" model and provides handling for the common case (fixed) and an explicit rejection for another special case (`is_private`, line 1329: `"sending private asset from AA"`), but for the third special asset property — `fixed_denominations` (indivisible) — there is neither: no explicit rejection/bounce that would let the AA/state machine notice failure, and no working transfer path either. The AA developer has no way to detect, from within oscript, that the reward/payout they scheduled for an indivisible asset was dropped, because bouncing (which would undo state changes) never happens — the unit is still considered a "successful" response.

### Impact Explanation
An AA that is designed to pay out an indivisible (fixed-denomination) asset — for example, an NFT-like coin, a bounty/rewards program built on an indivisible asset, or a marketplace/vault AA holding mixed asset types — will have that specific payout silently disappear. Because `handleSuccessfulEmptyResponseUnit` still commits the AA's `bounce_fees`-passing trigger as fully processed and finalizes `stateVars`, any internal ledger the AA keeps (e.g., "this address is now owed 0 units" or "order filled") becomes permanently desynchronized from reality: the recipient never receives the promised indivisible asset, and the AA has no further trigger to retry the transfer since its state already reflects the payment as done. This results in AA fund freezing / loss for depositors and reward recipients relying on indivisible-asset payouts, matching the "AA fund loss or freezing" impact category.

### Likelihood Explanation
Any AA author who defines `payment` messages parameterized by a variable asset (e.g., `trigger.data.asset`, or an asset chosen via a data feed / stored in state, similar to reward tokens chosen by a market-maker/reward pool in RecipeOrderbook) can trigger this path merely by having that asset be indivisible (`fixed_denominations: true`), which is a completely normal, permitted asset type creatable via the standard `asset` message (`fixed_denominations` and `denominations` are documented, supported fields — see `aa_validation.js:293-336`, `validation.js:2725-2755`). No malicious actor is required: an ordinary user or AA author choosing to reward/pay out in an indivisible asset — a routine, unprivileged configuration choice — reaches this bug. This is a design gap that will reproducibly occur whenever an AA is programmed to send an indivisible asset.

### Recommendation
When `objAsset.fixed_denominations` is detected in the message-preparation loop, do not silently skip the message. Either:
1. Bounce the trigger immediately with an explicit error (e.g., `"AAs cannot send fixed-denomination assets"`), before any state changes/`executeStateUpdateFormula` are committed, so the entire response (including state updates) is rolled back consistently with how `is_private` is already handled at line 1330; or
2. If silent dropping is intentional behavior for irrelevant/zero-value messages, ensure this specific "unsupported asset type" case is distinguished from ordinary "no messages" cases and surfaces as a bounce, not a "successful empty response," so that any state changes recording the (never-sent) payment are also rolled back.

### Proof of Concept
1. Define an indivisible asset `A` via a standard `asset` message with `fixed_denominations: true` and `denominations: [...]` (any user can do this, unprivileged).
2. Deploy an AA whose oscript, on trigger, updates `state` to mark an obligation as fulfilled (e.g., `state[...].paid = 1`) and emits a `payment` message with `asset: 'A'` sending some amount of `A` to the triggering address (mirroring a "reward payout" flow).
3. Send the AA's balance some units of asset `A` beforehand (via issuance/transfer) so a naive check of "AA holds the asset" passes.
4. Fire the trigger. Observe in `aa_composer.js::sendUnit`:
   - The payment message for asset `A` hits `objAsset.fixed_denominations` at [3](#0-2)  and is skipped without error.
   - It is subsequently filtered out at [4](#0-3) .
   - If that message was the only one, `handleSuccessfulEmptyResponseUnit(null)` is invoked, and the AA's `state[...].paid = 1` update (already computed by `executeStateUpdateFormula`) is persisted even though asset `A` was never sent to the recipient — verifiable by checking `aa_balances` for the AA (unchanged) versus the recipient's `outputs` table (no new row for asset `A`), while `state` in `aa_state_vars`/`storage` shows the obligation marked fulfilled.

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
