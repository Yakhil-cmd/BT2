### Title
Front-running of shared AA state/balance enables griefing and forced fund loss via bounce fees - (File: aa_composer.js)

### Summary
Any Autonomous Agent (AA) whose payout logic depends on the AA's current balance or a shared state variable (e.g. constant-product market makers, order books, or any rate/ratio computed from `balance[...]` or `var[...]`) is vulnerable to the same "front-run and change the rate" attack described in the external report. An attacker can post a trigger to the AA immediately before a victim's trigger is processed, shifting the balance/state that the victim's formula reads. When the victim's formula then produces an amount that violates the AA's own checks (e.g. `bounce('wrong ratio...')`, `bounce('not enough balance...')`), the AA calls `bounce()`, and the victim's bounce fee is unconditionally consumed rather than refunded, causing a concrete, unrecoverable loss of funds for the victim.

### Finding Description
Many oscript AAs compute a rate/ratio from the AA's live balance or a state variable that any unprivileged unit poster can influence, e.g. the reference Uniswap-like market maker sample: [1](#0-0) 
computes `$current_ratio = $asset_balance / $bytes_balance` and bounces if the caller's expected amount doesn't match: `bounce('wrong ratio of amounts, expected ' || $expected_asset_amount ...)`. Because AA triggers are processed asynchronously (each trigger is a separately posted unit, ordered deterministically only once stabilized), an attacker who observes a pending trigger to such an AA can post a second trigger that changes `balance[...]`/`var[...]` before the victim's trigger is executed, forcing the victim's computed values to diverge from what they expected and triggering `bounce()`.

The critical amplifying factor is in the core AA execution engine itself: when a primary trigger bounces, `aa_composer.js`'s `bounce()` function unconditionally deducts `bounce_fees` from the trigger's received outputs, and if the fee is greater than or equal to the amount received, none of it is refunded to the sender at all: [2](#0-1) 
Specifically:
- `bounce_fees.base` is deducted regardless of what caused the bounce (line 934, `var fee = bounce_fees[asset] || 0;`).
- If `fee > amount`, the function returns without sending any refund (`if (fee > amount) return finish(null);`), so the entire payment is lost.
- If `fee === amount`, likewise no refund is sent.

This means an attacker doesn't need to steal funds directly — they only need to manipulate the AA's shared balance/state (via their own, cheaper trigger) so that the victim's trigger's business logic bounces, at which point the protocol-level bounce-fee mechanism guarantees the victim forfeits real bytes (and equivalent for other assets, per `bounce_fees[asset]` handling) with no recourse.

### Impact Explanation
This directly maps to the "Medium" bug class in the external report: a griefing/DoS vector where a legitimate user's transaction with a rate/ratio dependent on shared, attacker-influenceable state is forced to fail, and — unlike a simple failed transaction on other platforms — the ocore bounce-fee mechanism guarantees actual loss of funds (`bounce_fees`) to the victim on every griefed attempt. This is a concrete "AA fund loss" impact reachable by any unprivileged unit poster who can afford to post competing trigger units to a shared AA.

### Likelihood Explanation
Any AA design that reads `balance[asset]` or state variables representing pooled liquidity/exchange rate (a common and encouraged oscript pattern, per the shipped uniswap-like/order-book samples) is exposed. The attack requires only the ability to post ordinary payment triggers to a public AA address, which is available to any user of the network, making this easily and cheaply repeatable to grief specific victims or their entire class of transactions.

### Recommendation
- In the AA execution engine (`aa_composer.js`), consider not charging bounce fees for the portion of a bounced amount that clearly exceeds what the victim intended to risk, or make bounce-fee behavior configurable/refundable when the bounce is caused by a documented slippage/rate check.
- At the oscript/template level, encourage (and document) slippage-protection idioms — passing an explicit minimum acceptable output/rate in `trigger.data` and having the AA bounce before any balance mutation if unmet — but since bounce fees are still lost under the current engine semantics, this only partially mitigates the fund-loss impact; the core fix belongs in how `bounce()` handles fee deduction relative to the failure cause.

### Proof of Concept
1. Deploy an oscript AA using the shipped `uniswap_like_market_maker.oscript` pattern (or any AA computing amounts from `balance[$asset]`/`balance[base]`).
2. Victim broadcasts unit U1: a trigger to "exchange bytes to asset" expecting ratio R based on currently known balances.
3. Attacker, upon seeing U1's presence, immediately broadcasts unit U2 (a small trigger to the same AA) that changes `balance[$asset]`/`balance[base]` (e.g., via the "invest/divest" or "exchange asset to bytes" branches), and gets it included/stabilized ahead of, or interleaved before, U1's AA-trigger processing.
4. When U1 is processed by `handleTrigger` in `aa_composer.js`, the AA's own ratio check (`if ($expected_asset_amount != trigger.output[[asset=$asset]]) bounce(...)`) fails because balances shifted.
5. `bounce()` (aa_composer.js:910-945) deducts `bounce_fees.base` from U1's outputs and, if the received amount is at or below the fee, sends nothing back — the victim's bytes are gone with no asset delivered. [3](#0-2)

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
