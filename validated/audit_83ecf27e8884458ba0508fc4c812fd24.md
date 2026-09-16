## Analog Found

### Title
AA balance-based "first deposit" check in the market-maker template can be permanently bricked by a sub-fee dust payment - (File: `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The bundled Uniswap-like market-maker AA template determines whether an incoming payment is the *initial* deposit by checking whether the AA's live token balances are zero (`$asset_balance == 0 OR $bytes_balance == 0`). Because `balance[...]` reflects the AA's total historical balance rather than a manually tracked "total shares outstanding" variable, and because Obyte's AA engine silently keeps coins it cannot afford to bounce, an attacker can permanently corrupt this zero-check with a single low-value trigger sent before any legitimate investor deposits.

### Finding Description
The AA's investment logic is: [1](#0-0) 

`$asset_balance` and `$bytes_balance` are derived from the AA's *actual* live balances (`balance[$asset]`, `balance[base]`), not from an independently tracked deposit total. The "initial deposit" branch (which seeds `var['mm_asset_outstanding']`) is only taken when *either* balance is exactly zero.

Separately, `aa_composer.js`'s bounce handling shows that a trigger unit which doesn't include enough base currency to cover the AA's `bounce_fees.base` cannot be refunded at all — the AA simply keeps the funds with no response and no state change: [2](#0-1) 

Combining these two facts: an attacker can send a single unit to the AA with a small amount of the paired asset (`$asset`) and a small amount of base bytes that is *non-zero but below the bounce fee* (e.g. below `constants.MIN_BYTES_BOUNCE_FEE`). This trigger matches none of the defined `cases` (it lacks the required `>1e5` base or the required `mm_asset_outstanding` state), so no case fires and no messages are produced. `bounce()` is then invoked, but because `trigger.outputs.base < bounce_fees.base`, the function returns without composing any refund message — the dust amounts of both the asset and base currency are permanently absorbed into the AA's balance without any accompanying state update.

When the first genuine investor later sends a real deposit (`base > 1e5` and `asset > 0`), the computed `$asset_balance` and `$bytes_balance` are now both non-zero (polluted by the attacker's leftover dust), so the `OR` check fails and the code falls through to the ratio-based branch instead of the "initial deposit" branch. Since `var['mm_asset_outstanding']` was never initialized (still `0`/falsy), `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` evaluates to `0`. Every subsequent investment also computes `$issue_amount` as a fraction of the still-zero `mm_asset_outstanding`, so it remains `0` forever — this is functionally identical to the reported `totalShares == 0` griefing bug in `Vault.sol`.

### Impact Explanation
Any unprivileged user who can post a single small-value unit to the AA address before the first legitimate investor deposits can permanently disable share issuance for that market-maker AA: all future investors receive `0` shares of the `$mm_asset` regardless of how much base currency they deposit, while their deposited bytes remain locked in the AA (no state change means they cannot be recovered through this AA's own logic). This constitutes a permanent freeze/loss of AA funds and issuance capability, matching the "Medium" severity of the referenced report.

### Likelihood Explanation
The attack requires only a single posted unit carrying a tiny amount of the underlying asset and an amount of base currency insufficient to cover the AA's bounce fee — both trivially affordable and requiring no special privileges, timing races, or cooperation from other parties. Any AA deployed from this template (or any derivative reusing the same zero-balance "initial deposit" idiom) is vulnerable the moment it is created and before its first real deposit.

### Recommendation
Do not infer "no shares issued yet" from the AA's live token balances. Track outstanding shares explicitly and independently (which this template already does via `var['mm_asset_outstanding']`) and use that variable's state — rather than `balance[...]` — as the sole condition for detecting the very first deposit, e.g. `if (!var['mm_asset_outstanding']) { ... }`. More generally, AA templates should never rely on `balance[asset]`/`balance[base]` being zero as a proxy for "nothing has been legitimately deposited," since balances can be polluted by unsolicited transfers that the AA engine cannot always refund (e.g., dust below the bounce fee).

### Proof of Concept
1. Attacker posts a unit paying the AA a small amount of `$asset` (e.g., `1`) and a small amount of `base` bytes that is less than `bounce_fees.base` (default `constants.MIN_BYTES_BOUNCE_FEE`).
2. None of the `cases` in `uniswap_like_market_maker.oscript` match (base isn't `>1e5`, `mm_asset_outstanding` is falsy), so the trigger falls to `bounce()`.
3. In `aa_composer.js`, `bounce()` sees `trigger.outputs.base < bounce_fees.base` and returns without issuing a refund — the dust stays in the AA's balance permanently, silently.
4. A legitimate investor later sends a proper deposit (`base > 1e5`, `asset > 0`). `$asset_balance` and `$bytes_balance` are now both non-zero due to the attacker's dust, so the `initial deposit` branch is skipped.
5. `$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding'])` evaluates to `0` because `mm_asset_outstanding` was never seeded.
6. All investors permanently receive `0` shares for any future deposit, since `mm_asset_outstanding` never becomes non-zero.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L33-48)
```text
			{ // invest in MM
				if: `{$mm_asset AND trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
						$issue_amount = balance[base];
						return;
					}
					$current_ratio = $asset_balance / $bytes_balance;
					$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
					if ($expected_asset_amount != trigger.output[[asset=$asset]])
						bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
					$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
					$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
				}`,
```

**File:** aa_composer.js (L909-929)
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
```
