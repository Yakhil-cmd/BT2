## Analysis

The Blueberry bug is a specific pattern: a required step of an unwind/repay flow (`remove_liquidity_one_coin`) depends on an external, single point of failure (`self.is_killed` in the Curve pool) that the calling contract cannot control or route around, and when that dependency permanently reverts, the calling contract has no fallback, so users cannot repay debt and lose funds.

The closest analogous reachable path in `ocore` is the **oscript `data_feed[[...]]` formula primitive**, which AAs use to fetch external data (oracle price feeds, etc.) to gate or compute a critical response (e.g., a payout, unwind, or liquidation calculation). If the oracle (equivalent of the "external protocol") stops publishing the referenced feed — the AA-level equivalent of `is_killed` becoming permanently true — every trigger that needs that feed to complete its logic aborts, exactly like `remove_liquidity_one_coin()` permanently reverting. [1](#0-0) 

## Title
AA logic that depends on `data_feed[[...]]` without an `ifnone` fallback can permanently bounce, locking user funds if the oracle stops publishing — (File: `formula/evaluation.js`)

## Summary
The `data_feed` formula operator used inside AA (autonomous agent) code aborts the whole trigger evaluation ("data feed X not found") if the referenced oracle has not posted a value and the AA author did not specify an `ifnone` fallback. If an AA's only path to release/repay/unwind funds for the trigger sender is gated on such a data-feed lookup, and the oracle stops posting (goes offline, is decommissioned, or simply never posts the exact feed_name/value the formula expects), that path becomes permanently unreachable — mirroring the Curve `is_killed` flag permanently blocking `remove_liquidity_one_coin()` in the referenced report.

## Finding Description
`data_feed[[...]]` is evaluated in `evaluate()`'s `'data_feed'` case: [2](#0-1)  If no value is found for the given oracle address(es)/feed name and no `ifnone` clause is present, the evaluation calls `setFatalError('error from data feed: '+err, ...)`, which propagates a fatal error up through `evaluateAA`/`handleTrigger` and forces the entire response unit to bounce: [3](#0-2)  A bounce reverts all pending state changes for that trigger (`bounce()`/`revert()` roll back the DB savepoint and restore state vars): [4](#0-3) 

The codebase's own bundled sample `futures_contract.oscript` demonstrates exactly this dependency and explicitly documents the failure mode in a comment: "data_feed will abort if the exchange rate not posted yet": [5](#0-4)  In that AA, users who sent collateral/asset tokens in exchange for USD/GB assets can only redeem/settle at the correct exchange rate by evaluating `data_feed[[oracles=..., feed_name='GBYTE_USD_MA_2019_04_30']]`. If the designated oracle (a single address, analogous to the Curve pool becoming killed) stops posting that specific feed permanently — due to being decommissioned, compromised, or simply discontinuing service — every trigger relying on that branch aborts and bounces indefinitely, and the value stored in the AA (the users' underlying collateral) cannot be settled through that path.

## Impact Explanation
If an AA's design (as templated/demonstrated in the ocore codebase itself) makes a critical settlement/withdrawal/unwind path solely conditional on a `data_feed[[...]]` lookup with no `ifnone` fallback and no alternative code path, an oracle going permanently silent (equivalent to `is_killed`) results in AA fund freezing: user assets held by the AA become permanently unreachable through that logic branch, exactly the "AA fund loss or freezing" impact class. This is a Medium-severity availability/fund-lock issue rather than a fund-theft issue, matching the severity of the referenced report (M-4).

## Likelihood Explanation
Likelihood depends on whether an AA author designs a critical path with a single, non-fallback data-feed dependency and no alternate settlement logic (as the bundled `futures_contract.oscript` sample does for its main exchange-rate branch when no `blackswan` event has been recorded and maturity has passed). Since `data_feed[[]]` "abort on missing value" is the default behavior of the oscript language absent an explicit `ifnone`, this is a systemic risk pattern reachable by any unprivileged AA author, and triggerable by any unprivileged sender simply by continuing to send triggers after the oracle stops posting.

## Recommendation
- Encourage/require AA templates that gate irreversible fund movements on `data_feed[[...]]` to always specify an `ifnone` fallback or a secondary, oracle-independent path to withdraw/settle funds (e.g., a timeout-based emergency withdrawal not requiring the feed).
- Consider adding lint/validation warnings in `aa_validation.js` when a `data_feed[[...]]` call inside a payment-triggering message branch lacks an `ifnone` parameter and has no alternative `case`/`if` branch that doesn't depend on the same feed.

## Proof of Concept
1. Deploy the bundled `futures_contract.oscript` AA (or an equivalent user AA) that gates its main settlement payment message on `data_feed[[oracles='X...', feed_name='GBYTE_USD_MA_2019_04_30']]` without `ifnone`: [6](#0-5) 
2. Users deposit `usd_asset`/`gb_asset` tokens expecting to redeem bytes after maturity via the exchange-rate branch.
3. The oracle at address `X55IWSNMHNDUIYKICDW3EOYAWHRUKANP` stops publishing the `GBYTE_USD_MA_2019_04_30` feed after maturity (analogous to Curve pool's `is_killed` becoming `true`).
4. Any trigger sent by a user attempting to redeem via that branch causes `data_feed[[...]]` to hit the "not found" path in `formula/evaluation.js` line 662, producing a fatal error that bounces the trigger: [7](#0-6) 
5. Since `bounce()` reverts state and returns only the trigger payment minus bounce fees, the user's underlying collateral tokens remain stuck in the AA with no way to complete redemption through that path, permanently, unless the AA happens to have an alternate branch (which is not guaranteed by the language and is absent from this exact code path once maturity has passed and no blackswan was recorded). [8](#0-7)

### Citations

**File:** formula/evaluation.js (L600-663)
```javascript
			case 'data_feed':

				function getDataFeed(params, cb) {
					if (typeof params.oracles.value !== 'string')
						return cb("oracles not a string "+params.oracles.value);
					var arrAddresses = params.oracles.value.split(':');
					if (!arrAddresses.every(ValidationUtils.isValidAddress))
						return cb("bad oracles "+arrAddresses);
					var feed_name = params.feed_name.value;
					if (!feed_name || typeof feed_name !== 'string')
						return cb("empty feed_name or not a string");
					var value = null;
					var relation = '';
					var min_mci = 0;
					if (params.feed_value) {
						value = params.feed_value.value;
						relation = params.feed_value.operator;
						if (!isValidValue(value))
							return cb("bad feed_value: "+value);
					}
					if (params.min_mci) {
						min_mci = params.min_mci.value.toString();
						if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
							return cb("bad min_mci: "+min_mci);
						min_mci = parseInt(min_mci);
					}
					var ifseveral = 'last';
					if (params.ifseveral){
						ifseveral = params.ifseveral.value;
						if (ifseveral !== 'abort' && ifseveral !== 'last')
							return cb("bad ifseveral: "+ifseveral);
					}
					var what = 'value';
					if (params.what){
						what = params.what.value;
						if (what !== 'unit' && what !== 'value')
							return cb("bad what: "+what);
					}
					var type = 'auto';
					if (params.type){
						type = params.type.value;
						if (type !== 'string' && type !== 'auto')
							return cb("bad df type: "+type);
					}
					if (params.ifnone && !isValidValue(params.ifnone.value))
						return cb("bad ifnone: "+params.ifnone.value);
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
					//	console.log(arrAddresses, feed_name, value, min_mci, ifseveral);
					//	console.log('---- objResult', objResult);
						if (objResult.bAbortedBecauseOfSeveral)
							return cb("several values found");
						if (objResult.value !== undefined){
							if (what === 'unit')
								return cb(null, objResult.unit);
							if (type === 'string')
								return cb(null, objResult.value.toString());
							return cb(null, (typeof objResult.value === 'string') ? objResult.value : createDecimal(objResult.value));
						}
						if (params.ifnone && params.ifnone.value !== 'abort'){
						//	console.log('===== ifnone=', params.ifnone.value, typeof params.ifnone.value);
							return cb(null, params.ifnone.value); // the type of ifnone (string, decimal, boolean) is preserved
						}
						cb("data feed " + feed_name + " not found");
					});
```

**File:** aa_composer.js (L589-615)
```javascript
	function evaluateAA(arrDefinition, cb) {
		var locals = {};
		var f = getFormula(arrDefinition[1].getters);
		if (f === null) { // no getters
			return replace(arrDefinition, 1, '', locals, '', cb);
		}
		// evaluate getters before everything else as they can define a few functions
		delete arrDefinition[1].getters;
		var opts = {
			conn: conn,
			formula: f,
			trigger: trigger,
			params: params,
			locals: locals,
			stateVars: stateVars,
			responseVars: responseVars,
			bStatementsOnly: true,
			bGetters: true,
			objValidationState: objValidationState,
			address: address
		};
		formulaParser.evaluate(opts, [], '/getters', function (err, res) {
			if (res === null)
				return cb(err.formattedError || "formula " + f + " failed: " + err);
			replace(arrDefinition, 1, '', locals, '', cb);
		});
	}
```

**File:** aa_composer.js (L910-945)
```javascript
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

**File:** aa_composer.js (L1759-1783)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
```

**File:** test/samples/futures_contract.oscript (L69-105)
```text
			// 1 GB is now 50 USD, 1 byte is 50e-9 = 5e-8 USD
			// 1 usd asset is always 2.5e-8 USD, 1 gb asset is 1 byte minus 2.5e-8 USD
			{ // pay bytes in exchange for the assets
				if: `{
					if (trigger.output[[asset!=base]].asset == 'none')
						return false;
					$gb_asset_amount = trigger.output[[asset=var['gb_asset']]];
					$usd_asset_amount = trigger.output[[asset=var['usd_asset']]];
					if ($gb_asset_amount < 1e4 AND $usd_asset_amount < 1e4)
						return false;
					if ($gb_asset_amount == $usd_asset_amount){ // helps in case the exchange rate is never posted
						$bytes = $gb_asset_amount;
						return true;
					}
					if (var['blackswan'])
						$bytes = $usd_asset_amount;
					else{
						if (timestamp < 1556668800)
							bounce('wait for maturity date');
						// data_feed will abort if the exchange rate not posted yet
						$exchange_rate = data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA_2019_04_30']];
						$bytes_per_usd_asset = min(50/$exchange_rate/2, 1);
						$bytes_per_gb_asset = 1 - $bytes_per_usd_asset;
						$bytes = round($bytes_per_usd_asset * $usd_asset_amount + $bytes_per_gb_asset * $gb_asset_amount);
					}
					true
				}`,
				messages: [{
					app: 'payment',
					payload: {
						asset: "base",
						outputs: [
							{address: "{trigger.address}", amount: "{ $bytes }"}
						]
					}
				}]
			},
```
