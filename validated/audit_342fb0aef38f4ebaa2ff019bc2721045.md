## Analysis

This maps to the reported bug class of **irrecoverable fund loss when a rescue/refund mechanism aborts because a narrow, per-item check fails, even though the rest of the bundled value should still have been returned**. The strongest reachable analog in `ocore` is Obyte's AA "bounce" mechanism, which is the *only* refund path an unprivileged unit-poster can trigger, and which — unlike Solidity contracts — has **no admin/owner rescue function at all**, so any coins it swallows are permanently unrecoverable (funds are immutable code, cannot be upgraded). [1](#0-0) 

### Title
Single insufficient asset in a multi-asset AA trigger aborts the entire bounce, permanently freezing bytes and other legitimately-refundable assets - (File: aa_composer.js)

### Summary
The `bounce()` function in `aa_composer.js` is the sole mechanism by which coins mistakenly or unexpectedly sent to an Autonomous Agent (AA) get returned to the sender when the AA logic fails or is unsatisfied. When a trigger unit carries multiple assets (e.g. base bytes plus a custom asset), `bounce()` iterates the assets and returns each amount minus its configured `bounce_fees`. However, if **any single asset's received amount is less than its configured `bounce_fees[asset]`**, the function does `return finish(null)` immediately [2](#0-1) , discarding the entire refund — including bytes and any other assets in the same trigger that individually had more than enough to be refunded. Since AAs are immutable (no code can be upgraded, and there is no owner/admin "rescue" call as in `ImmutableBundle.rescueERC721`), the swallowed coins become permanently stuck in the AA's balance unless the AA's own business logic happens to have an unrelated code path that spends them out — which most AA scripts do not provide for arbitrary/unexpected assets.

### Finding Description
`handleTrigger` computes `bounce_fees` from the AA's own definition (`template.bounce_fees || {base: MIN_BYTES_BOUNCE_FEE}`) [3](#0-2) . Before evaluating the AA formulas, for each asset present in the trigger, if the amount received for that asset is below the asset's configured bounce fee, the code explicitly invokes `bounce(...)`, describing this in its own comment as something that should happen "silently" per-asset: [4](#0-3) 

Inside `bounce()`, the refund is built by iterating over `trigger.outputs` (all assets present in the same trigger unit) and computing `bounced_amount = amount - fee` for each: [5](#0-4) 

But the check `if (fee > amount) return finish(null);` fires on the *first* asset encountered whose amount is under its fee, and returns immediately with `finish(null)` — meaning **no payment message at all is created**, not even for assets that had ample balance to be refunded (e.g., the base bytes payment that funded the whole transaction). `finish(null)` results in the AA accepting the unit with an empty response and no state change, but the balances already credited to the AA in `updateInitialAABalances` (see the `INSERT`/`UPDATE aa_balances` logic) remain permanently in the AA's balance table: [6](#0-5) 

Because AA definitions are content-addressed and cannot be modified after deployment (unlike `ImmutableBundle`, which at least has an owner who can call `rescueERC721` for non-bundle tokens), there is no protocol-level or admin-level way to extract these funds once the AA's own script logic offers no path to spend an unexpected/undersized secondary asset back out. This exactly parallels the reported issue: value that should be returned via the designated "safe" path (bounce/rescue) is unrecoverable because the guard condition is evaluated too coarsely (per-transaction abort instead of per-asset skip).

### Impact Explanation
This causes genuine, unrecoverable **AA fund freezing**: an attacker (or even an honest user, e.g. a wallet that automatically attaches a dust amount of some custom asset alongside a legitimate byte payment) can cause any amount of bytes/base currency and any other assets bundled in the same trigger unit to become permanently locked in the AA, with zero response and zero possibility of retrieval, since AAs cannot be upgraded and have no owner-level recovery function. This is strictly worse than the original NFTfi report, where at least an `onlyOwner` rescue path existed (even if buggy) — in ocore, no rescue path exists once the bounce aborts.

### Likelihood Explanation
This is trivially triggerable by any unprivileged unit poster: only requires composing a trigger unit that sends the AA a legitimate base-byte payment (or other asset) together with a second asset whose amount is smaller than the AA's declared `bounce_fees` for that asset. No special privileges, no race condition, and no specific chain of AA responses are required — a single crafted unit suffices.

### Recommendation
In `bounce()`, when the check `fee > amount` triggers for a given asset, that asset alone should be treated as "kept as dust/fee" (consistent with the intended per-asset "ignore silently" comment), while the loop should `continue` to still refund all other assets (including base bytes) that had sufficient balance, instead of aborting the whole refund with `return finish(null)`.

### Proof of Concept
1. Deploy an AA with `bounce_fees: { base: 10000, "<asset_hash>": 5000 }` and any simple message logic (e.g. `sample bank_without_percent.oscript`-style logic) that would otherwise refund on failure. 
2. Post a trigger unit that pays this AA `20000` base bytes and `1000` units of `<asset_hash>` (below its 5000 bounce fee) in the same unit, with a `trigger.data` payload designed to fail the AA's condition checks. 
3. Observe: `handleTrigger` detects `trigger.outputs[asset] < bounce_fees[asset]` for `<asset_hash>` and calls `bounce(...)` [7](#0-6) . 
4. Inside `bounce()`, the loop reaches the `<asset_hash>` entry, finds `fee (5000) > amount (1000)`, and calls `return finish(null)` [8](#0-7)  — discarding the refund of the 20000 bytes as well, even though those bytes alone exceeded the base bounce fee and would normally have been returned. 
5. The 20000 bytes (and the 1000 asset units) remain credited to the AA's balance in `aa_balances` forever, with no way for the sender or anyone else to retrieve them, since the AA definition is immutable and has no built-in path to spend out an unrecognized/undersized secondary asset.

### Citations

**File:** aa_composer.js (L446-448)
```javascript
	var bounce_fees = template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE};
	if (!bounce_fees.base)
		bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
```

**File:** aa_composer.js (L491-524)
```javascript
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
```

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
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
	}
```

**File:** aa_composer.js (L1855-1859)
```javascript
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```
