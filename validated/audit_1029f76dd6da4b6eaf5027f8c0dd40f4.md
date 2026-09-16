### Title
Bounce logic aborts refund of all trigger assets when a single asset underfunds its bounce fee - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `bounce()` function iterates over all assets received in a trigger unit to build refund messages. If any single asset in that iteration doesn't cover its configured `bounce_fees[asset]`, the function immediately aborts (`return finish(null)`) and discards the refund messages already built for every other asset that was properly funded, causing the AA to silently retain all of the sender's coins instead of bouncing back the excess.

### Finding Description
When an AA response bounces (for any reason — a formula error, insufficient state, `evaluateAA` failure, etc.), `bounce()` is invoked to construct refund payment messages for every asset present in `trigger.outputs`: [1](#0-0) 

```
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

The loop treats a single "bad" asset (one whose amount doesn't cover its configured `bounce_fees[asset]`) as fatal for the *entire* bounce, discarding messages already queued for every other, correctly-funded asset (including the base-currency refund). `finish(null)` means no response unit is produced at all, so none of the trigger's coins — base bytes or any other asset — are returned to the sender; the AA silently keeps everything.

This is directly reachable by an unprivileged unit poster: any account can send a trigger unit to an AA carrying multiple asset payments (e.g., bytes plus a custom asset) where one of the assets happens to be below the AA's configured `bounce_fees` threshold for that asset. If the AA's business logic subsequently bounces for any unrelated reason (invalid trigger data, insufficient balance, `if`/`init` formula failure, etc.), the entire trigger's funds — not just the underfunded asset — are lost, because `bounce()` unconditionally short-circuits on the first asset that fails the fee check, discarding messages already computed for the other assets.

Note the earlier pre-check at lines 1855-1859 also calls `bounce()` as soon as it finds any asset that can't cover its fee, so in practice this scenario is trivially triggerable by a single well-formed multi-asset trigger unit. [2](#0-1) 

### Impact Explanation
This causes silent, unauthorized fund loss/freezing for the trigger sender: bytes and other assets sent to the AA that would normally be bounced back (minus the small bounce fee) are instead entirely retained by the AA whenever any single asset in the same trigger fails to cover its own bounce fee. This qualifies as concrete AA fund loss for an unprivileged party, matching the "single bad element blocks the whole loop, causing fund loss" bug class from the reference report (a bad collateral/asset item preventing correct handling of the rest of the batch).

### Likelihood Explanation
Any user can construct a trigger unit that pays multiple assets to an AA in a single unit (this is standard multi-asset payment composition supported by the protocol). Triggering a bounce afterward (e.g. by supplying data the AA's formulas reject) is trivial and entirely under the sender's control. No special privileges, timing, or race conditions are required.

### Recommendation
In `bounce()`, do not abort the whole refund construction when a single asset fails its fee check. Instead, skip that specific asset (treat its balance as consumed by the fee, similar to the `fee === amount` branch) and continue building refund messages for the remaining, properly-funded assets, so that a single underfunded asset cannot cause loss of all other assets/bytes in the same trigger.

### Proof of Concept
1. Deploy an AA with `bounce_fees: {base: 10000, ASSET_X: 100}` and any formula logic that can bounce (e.g., `bounce("some check failed")` triggered by a crafted `data` payload).
2. Send a trigger unit to this AA that pays: `base: 100000` bytes and `ASSET_X: 50` (i.e., below the 100-unit bounce fee for `ASSET_X`), while including data that makes the AA logic bounce.
3. In `bounce()`, the loop iterates `trigger.outputs`; when it reaches `ASSET_X` it evaluates `fee (100) > amount (50)` and immediately calls `return finish(null)`, discarding the already-queued base-currency refund message (100000 - 10000 = 90000 bytes that should have been returned).
4. Result: the sender loses the entire 100000 bytes and 50 units of `ASSET_X` to the AA, instead of only losing the 50 units of `ASSET_X` (which alone doesn't cover its fee) while getting back 90000 bytes.

### Citations

**File:** aa_composer.js (L930-944)
```javascript
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

**File:** aa_composer.js (L1850-1859)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
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
