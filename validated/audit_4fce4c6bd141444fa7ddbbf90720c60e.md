## Summary

Ocore's AA execution engine credits every payment sent to an Autonomous Agent's `aa_balances` ledger unconditionally, even when the payment doesn't match any business-logic branch of the AA and no state variables are updated to record it. AAs that use the raw `balance[asset]` formula (rather than an internally tracked accounted state variable) to compute investment ratios, share issuance, or payout amounts — a pattern actively used and recommended in ocore's own sample AAs — can have those calculations skewed by anyone who sends un-accounted "donations" (or by unavoidable bounce-fee retention) to the AA address. This is the same root-cause pattern as the Euler Finance incident: funds credited to a balance/reserve without a corresponding accounting/liquidity check, later consumed by a formula that trusts the raw balance.

## Finding Description

When a trigger unit is processed, `updateInitialAABalances` unconditionally adds the trigger's payment outputs to the AA's `aa_balances`/`assocBalances` *before* any business logic (the `if` conditions of `messages`/`cases`) is evaluated: [1](#0-0) 

If, after evaluating the AA's `messages` template, no message's `if` condition is true and the message array becomes empty, ocore treats this not as a bounce but as a **successful empty response**: the received coins stay credited to the AA's balance, no response unit is sent, and no state variables change: [2](#0-1) 

This is confirmed by the "no outputs" test, whose comment explicitly states this behavior: [3](#0-2) 

Additionally, even a *bounced* trigger permanently donates `bounce_fees` to the AA's balance with no state-var accounting: [4](#0-3) 

Subsequent legitimate operations that read `balance[asset]` via the `balance` formula operator pull directly from this same raw, donation-inflated ledger: [5](#0-4) 

Ocore's own sample AA, a Uniswap-like market maker, exemplifies the vulnerable pattern: investment ratio, exchange price, and divestment payouts are all computed from raw `balance[...]` rather than an internally tracked reserve: [6](#0-5) [7](#0-6) [8](#0-7) 

Because `balance[base]`/`balance[$asset]` includes every silently-absorbed donation or retained bounce fee that was never reflected in `var['mm_asset_outstanding']`, any unprivileged unit poster can inflate the AA's recorded balance without increasing the tracked share count. A subsequent `divest` call then computes `round($investor_share * balance[$asset])` / `round($investor_share * balance[base])` against the inflated balance, over-paying whichever shareholder divests next relative to their true proportional claim — draining value from remaining shareholders. This mirrors Euler's exploit mechanics exactly: donate to inflate an unchecked balance, then invoke a function whose payout/eligibility math trusts that balance.

## Impact Explanation

Any AA holding pooled/shared funds and computing payouts, ratios, or issuance from `balance[...]` instead of a strictly-incremented accounted state variable is exposed to fund-loss for its depositors: an attacker can donate bytes/assets (via a trigger that fails all `if` conditions, or via repeated small triggers that only pay bounce fees) to inflate the AA's balance, then immediately divest/withdraw to capture a disproportionate share of the pool, or cause a following investor's expected-ratio check to fail/succeed incorrectly. This is a concrete AA fund-loss/mis-accounting vector reachable by any address capable of posting a unit with a payment output to the target AA — no privileged role required.

## Likelihood Explanation

The mechanism requires no special privileges: any unit poster can send a plain payment to a public AA address. Ocore's own bundled sample scripts (`uniswap_like_market_maker.oscript`, `fundraising_proxy.oscript`) demonstrate that using raw `balance[...]` for share/ratio math is an encouraged, documented pattern, making this analog broadly applicable to real AAs deployed using this idiom, not a hypothetical edge case.

## Recommendation

- Document prominently (and where feasible enforce via `aa_validation.js`) that AAs must never use `balance[asset]` directly for payout/ratio/share computations tied to pooled investor funds; instead they must maintain and rely exclusively on explicit state variables that are incremented/decremented in lock-step with every payment they intend to account for.
- Consider having `handleSuccessfulEmptyResponseUnit`/bounce paths emit a distinguishable marker (or optionally bounce fully) for un-accounted absorbed coins and bounce fees, so wallets/AA authors can detect balance drift from tracked state.
- Provide/require a "sweep to reserve state var" idiom in official sample AAs (`uniswap_like_market_maker.oscript`, `order_book_exchange.oscript`, `a_bank_without_percent.oscript`) instead of the current `balance[...]`-based patterns, since these are widely copied as templates.

## Proof of Concept

1. Deploy an AA following the `uniswap_like_market_maker.oscript` pattern (invest/divest/exchange based on raw `balance[...]`, `var['mm_asset_outstanding']` tracking share count only).
2. Attacker A invests a minimal amount to receive shares (`mm_asset_outstanding` now = A's shares).
3. Attacker sends repeated trigger units to the AA that fail every `if` condition in the AA's `cases` (or send just above `MIN_BYTES_BOUNCE_FEE` without other matching data), causing `bounce_fees.base` to be retained in `aa_balances` every time per [9](#0-8) , or crafts a unit that lands in the generic "no messages after filtering" absorption path per [10](#0-9) , inflating `balance[base]` with no change to `mm_asset_outstanding`.
4. Attacker A calls `divest` with their shares; payout is computed as `round($investor_share * balance[base])` using the now-inflated `balance[base]`, letting A withdraw more bytes than their fair share of contributed capital, at the expense of remaining/future shareholders.

### Citations

**File:** aa_composer.js (L475-490)
```javascript
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
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

**File:** aa_composer.js (L1868-1877)
```javascript
			var messages = template.messages;
			if (!messages)
				return bounce('no messages');
			// this will also filter out the special message that performs the state changes
			messages = messages.filter(function (message) { return (isNonemptyObject(message) && 'payload' in message && (message.app !== 'payment' || isNonemptyObject(message.payload) && Array.isArray(message.payload.outputs))); });
			if (messages.length === 0) { // eat the received coins and send no response, state changes are still performed
				error_message = 'no messages after filtering';
				console.log(error_message);
				return handleSuccessfulEmptyResponseUnit(null);
			}
```

**File:** test/aa.test.js (L984-1017)
```javascript
	var aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{if: "{trigger.data.nonexistent}", address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 2000}"}
					]
				}
			}
		]
	}];
	var address = objectHash.getChash160(aa);
	db.takeConnectionFromPool(conn => {
		conn.query('BEGIN');
		conn.query("INSERT INTO aa_addresses (address, definition, unit, mci) VALUES(?, ?, ?, ?)", [address, JSON.stringify(aa), objMcUnit.last_ball_unit, 500]);
		conn.query("INSERT INTO outputs (unit, message_index, output_index, address, amount) VALUES(?, 0, 4, ?, ?)", [objMcUnit.unit, address, trigger.outputs.base]);
		conn.query("DELETE FROM aa_responses WHERE trigger_unit=? AND aa_address=?", [trigger.unit, address]);

		var objUnit;
		writer.saveJoint = function (objJoint, objValidationState, preCommitCallback, onDone) {
			console.log("mock saving unit", JSON.stringify(objJoint, null, '\t'));
			objUnit = objJoint.unit;
			onDone();
		}
		
		aa_composer.handleTrigger(conn, batch, trigger, {}, stateVars, aa, address, 600, objMcUnit, false, arrResponseUnits, (objResponseUnit, bounce_message) => {
			conn.query('ROLLBACK', () => {
				conn.release();
			});
			t.deepEqual(bounce_message, 'no messages after filtering, then no state changes');
			t.deepEqual(objUnit.messages.find(function (message) { return (message.app === 'payment'); }).payload.outputs.find(function (output) { return (output.address === trigger.address); }).amount, 30000);
```

**File:** formula/evaluation.js (L1510-1528)
```javascript
				function readBalance(param_address, bal_asset, cb2) {
					if (bal_asset !== 'base' && !ValidationUtils.isValidBase64(bal_asset, constants.HASH_LENGTH))
						return setFatalError('bad asset ' + bal_asset, { arr }, false, cb);

					if (!objValidationState.assocBalances[param_address])
						objValidationState.assocBalances[param_address] = {};
					var balance = objValidationState.assocBalances[param_address][bal_asset];
					if (balance !== undefined)
						return cb2(new Decimal(balance));
					conn.query(
						"SELECT balance FROM aa_balances WHERE address=? AND asset=? ",
						[param_address, bal_asset],
						function (rows) {
							balance = rows.length ? rows[0].balance : 0;
							objValidationState.assocBalances[param_address][bal_asset] = balance;
							cb2(new Decimal(balance));
						}
					);
				}
```

**File:** test/samples/uniswap_like_market_maker.oscript (L33-47)
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
```

**File:** test/samples/uniswap_like_market_maker.oscript (L67-93)
```text
			{ // divest MM shares 
				// (user is already paying 10000 bytes bounce fee which is a divest fee)
				// the price slightly moves due to fees received and paid in bytes
				if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
				init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
							]
						}
					},
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[base]) }"}
							]
						}
					},
```

**File:** test/samples/uniswap_like_market_maker.oscript (L102-123)
```text
			{ // exchange bytes to asset
				if: `{trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] == 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_asset_balance = round($p / balance[base]);
					$amount = $asset_balance - $new_asset_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```
