### Title
All-or-nothing bounce_fee check discards refunds for all assets when a single asset's fee exceeds its sent amount - (File: aa_composer.js)

### Summary
The C4 report describes a fee-precision bug: a flat, atomic-unit-denominated price (`tokenGasPrice`) that ignores a token's decimals causes disproportionate overcharge relative to a user's transferred value. In ocore's AA (Autonomous Agent) engine, `bounce_fees` plays the exact same role as `tokenGasPrice`: a fixed, per-asset integer amount denominated in raw atomic units, set once by the AA author, with no adjustment for the relative "value per atom" of different assets. The core protocol code that consumes this parameter contains a bug where a single under-funded asset causes total loss of an otherwise-refundable multi-asset trigger.

### Finding Description
When an AA trigger fails and must be bounced, `bounce()` iterates over every asset the trigger sent and computes a refund minus the AA's configured `bounce_fees[asset]`: [1](#0-0) 

```
var messages = [];
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

If *any single asset* in `trigger.outputs` has `bounce_fees[asset] > amount_sent`, the function immediately `return finish(null)` — aborting the entire refund, including any other assets (and base bytes) that were already computed and pushed into `messages` but not yet sent. The AA keeps 100% of everything the trigger sender transferred, instead of only failing to refund the one under-funded asset.

`bounce_fees` is set by the AA author as a flat integer amount per asset (analogous to `tokenGasPrice`), independent of the asset's actual decimals/value-per-atom: [2](#0-1) 

The default only covers the base asset (`MIN_BYTES_BOUNCE_FEE`); any AA that also configures a fee for a secondary asset (common for multi-asset AAs like token issuers or market makers, cf. `test/samples/create_an_asset.oscript`) is exposed. Because the check earlier only verifies `trigger.outputs.base >= bounce_fees.base` before entering `bounce()`: [3](#0-2) 

a trigger can pass the initial "can we afford to bounce" gate on the base asset yet still be fully swallowed later if it also carries a small amount of a second asset whose configured `bounce_fees[asset]` is high relative to what was actually sent — exactly the WatchPug-style scenario of a fixed atomic fee being disproportionate to a low-decimal/high-value token amount.

### Impact Explanation
Any unprivileged AA trigger sender who sends a multi-asset payment (e.g., valuable base bytes plus a small/dust amount of another asset the AA has a configured `bounce_fees` for) and whose trigger ends up bouncing (due to any AA error/validation failure) loses the *entire* transferred value — including the base-byte portion that would ordinarily have been fully refunded — rather than only forfeiting the smaller asset. This is a direct AA fund-loss bug reachable by any trigger sender and does not require attacker collusion with the AA author; it can be tripped accidentally by wrong trigger data/dust outputs, or exploited deliberately by an AA author (or a griefer crafting a poison output) to confiscate funds that should have bounced back.

### Likelihood Explanation
Likelihood is Medium: it requires (1) an AA that defines `bounce_fees` for a non-base asset (a normal pattern for multi-asset AAs), and (2) a trigger that bounces while carrying more than one asset, one of which is below its configured fee. AA bounces are common (any formula/condition failure triggers `bounce()`), and sending trigger outputs in multiple assets is normal AA usage, making the precondition easy to hit unintentionally, and trivially reproducible by any user or bot interacting with such an AA.

### Recommendation
Change the loop in `bounce()` so an under-funded asset only forfeits its own amount instead of aborting the whole refund — i.e., replace `if (fee > amount) return finish(null);` with logic that skips sending a refund message for that one asset (treating its full amount as the bounce fee) while still sending refund messages for all other assets that were fully computed. Ensure this doesn't change consensus-critical unit content unexpectedly (needs a protocol upgrade MCI gate like other consensus behavior changes in this codebase, e.g. `pemCurvesFixMci`).

### Proof of Concept
1. AA definition: `bounce_fees: { base: 10000, ASSET_X: 1000000 }`.
2. Attacker/user sends a trigger unit with `trigger.outputs = { base: 50000, ASSET_X: 1 }` (1 atomic unit of ASSET_X, far below the configured 1,000,000 fee) that is designed to fail AA evaluation (e.g., malformed `data`), forcing a bounce.
3. In `bounce()`, the pre-check `trigger.outputs.base (50000) >= bounce_fees.base (10000)` passes, so the loop begins.
4. Iterating over `trigger.outputs`: for `ASSET_X`, `fee (1000000) > amount (1)` is true → `return finish(null)` is executed immediately, discarding any messages already built for `base`.
5. Result: the AA keeps all 50000 bytes and the 1 unit of ASSET_X; the trigger sender receives no refund at all, despite having sent far more than the base bounce fee and being entitled to a ~40000-byte refund. [4](#0-3)

### Citations

**File:** aa_composer.js (L446-448)
```javascript
	var bounce_fees = template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE};
	if (!bounce_fees.base)
		bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
```

**File:** aa_composer.js (L928-944)
```javascript
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
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
