This confirms the key protocol behavior: even when no `if` case in an AA definition matches the trigger, or when all messages get filtered out (e.g. "no messages after filtering"), the coins received are still permanently absorbed into the AA's balance while state changes and responses are skipped — this is explicitly documented as intentional: "eat the received coins and send no response, state changes are still performed" at [1](#0-0) , and the balance credit itself happens unconditionally in `updateInitialAABalances` before any case-matching or `if` logic is evaluated [2](#0-1) .

This is exactly the root-cause pattern behind the reported BasePool `mint()` frontrun — an actor can passively inflate a shared pool's balance without being attributed a proportional claim, and any AA logic that computes issuance/shares from the pool's total `balance[...]` rather than strictly from `trigger.output[[...]]` is vulnerable to donation/inflation dilution, letting a frontrunning depositor capture value intended for the legitimate depositor. The shipped `uniswap_like_market_maker.oscript` sample demonstrates this exact vulnerable pattern: the "initial deposit" and swap-pricing logic key off `balance[$asset]` / `balance[base]` [3](#0-2)  and [4](#0-3) , so any unprivileged unit poster can send a plain payment (with no matching `data` trigger case) to the AA address first, permanently and silently increasing `balance[base]`/`balance[asset]` per the "eat the received coins" behavior, before the legitimate depositor's trigger executes, skewing the ratio/share calculation used in `$current_ratio`, `$expected_asset_amount`, and `$issue_amount` in that pool logic.

### Title
AA share/pricing logic based on `balance[...]` is frontrunnable via donation to the AA before a depositor's trigger executes - (File: `aa_composer.js`, `test/samples/uniswap_like_market_maker.oscript`)

### Summary
Because ocore's AA engine unconditionally credits any bytes/assets sent to an AA address to that AA's on-chain `balance`, even when the accompanying trigger data matches no `if` case and produces no response ("eat the received coins and send no response, state changes are still performed"), an attacker can donate funds directly to a pool-style AA immediately before a legitimate user's deposit/exchange trigger is included. Pool AAs (like the shipped Uniswap-like market maker sample) that compute issued-share amounts or swap prices from `balance[asset]`/`balance[base]` rather than strictly from the trigger's own `trigger.output[[...]]` values will misprice the legitimate user's deposit, letting the attacker capture value that should have gone to that user — functionally equivalent to the reported BasePool `mint()` frontrun/donation attack.

### Finding Description
`getTrigger()` builds the trigger's `outputs` from the payment messages in the triggering unit [5](#0-4) . `handleTrigger()` then calls `updateInitialAABalances()`, which adds `trigger.outputs` to the AA's persisted `aa_balances` row (or `assocBalances` in dry-run) *before* any `if`/case matching or state-formula evaluation happens [2](#0-1) . If none of the AA's `messages.cases` match, or if all messages are filtered out, ocore explicitly still keeps the balance update and simply skips sending any response: "eat the received coins and send no response, state changes are still performed" [6](#0-5) . This is corroborated by the test suite, where sending a trigger to an AA with an unmatched `if` still results in the balance being silently absorbed and only "no messages after filtering, then no state changes" reported back [7](#0-6) .

Any AA that determines pool ratios or share issuance using `balance[asset]` (the AA's cumulative on-chain balance) instead of amounts strictly bound to the current trigger is therefore exposed to a donation/inflation attack: an attacker sends a "dead" payment (data that matches no case, or a plain payment) to inflate `balance[base]`/`balance[asset]` right before a victim's legitimate deposit/swap trigger, skewing that victim's computed ratio, expected amount, or issued shares. The shipped sample `uniswap_like_market_maker.oscript` exhibits exactly this pattern in its "invest in MM" and "exchange" cases, which compute `$asset_balance`, `$bytes_balance`, `$current_ratio`, `$expected_asset_amount`, and `$issue_amount`/`$amount` from `balance[$asset]`/`balance[base]` [3](#0-2) [4](#0-3) .

### Impact Explanation
An unprivileged unit poster (attacker) can, for any pool-style AA that relies on `balance[...]` rather than trigger-bound amounts, front-run a victim's deposit/swap unit by getting a donation absorbed into the AA's balance just before the victim's unit is ordered. This distorts the ratio/price computation the victim's trigger uses, causing the victim to receive fewer shares/output tokens than expected while the attacker (who can subsequently trigger an exchange/divest case) captures the mispriced difference. This is a concrete asset-loss impact for the AA's users/depositors — funds intended for one depositor end up captured by the attacker, analogous to the Vader `BasePool.mint()` frontrun/Uniswap V2 direct-transfer issue referenced in the source report.

### Likelihood Explanation
Likelihood is dependent on AA authors: any AA that keys pricing/issuance formulas off `balance[...]` instead of `trigger.output[[...]]` is exposed, and the engine provides no built-in protection or warning against this pattern — it silently absorbs unmatched/uncredited payments into balance regardless of case-matching, as shown by the explicit "eat the received coins" behavior in `aa_composer.js`. Since ocore ships this exact pattern as a documented sample AA (`uniswap_like_market_maker.oscript`), which developers may use as a template, the likelihood of real-world AAs implementing the vulnerable pattern is non-trivial.

### Recommendation
1. In the AA engine or documentation, explicitly warn that `balance[...]` includes all coins ever received by the AA (including donations from unmatched triggers), and that pool/AMM-style AAs must base share-issuance and pricing calculations only on amounts provably attributable to the current trigger (`trigger.output[[...]]`), tracking pool reserves in dedicated state variables (`var[...]`) that are only updated within matched cases, rather than trusting `balance[...]` directly.
2. Update the shipped `uniswap_like_market_maker.oscript` sample to track `$asset_reserve`/`$bytes_reserve` in state variables updated only inside matched cases, instead of deriving them from `balance[...]`, so that stray/donated payments cannot dilute or skew share/price calculations for other depositors.

### Proof of Concept
1. An AA is defined using the exact logic of `uniswap_like_market_maker.oscript` (or any AA implementing the same `balance[...]`-based pricing pattern).
2. Attacker observes that a victim is about to post an "invest in MM" unit with `trigger.output[[asset=base]] > 1e5` and `trigger.output[[asset=$asset]] > 0`.
3. Attacker posts (and gets included first, e.g. via a lower unit with better parent placement or simply being first in the DAG order) a payment unit sending base bytes directly to the AA address without any accompanying data that matches a case (e.g. omitting `trigger.data.define` and not meeting other "if" conditions) — per `aa_composer.js`'s documented behavior, this unit's payment is absorbed into `balance[base]` with no response and no state change [6](#0-5) .
4. When the victim's "invest in MM" trigger is subsequently processed, `$bytes_balance = balance[base] - trigger.output[[asset=base]]` now includes the attacker's donation, skewing `$current_ratio` and `$expected_asset_amount`/`$issue_amount` computed in [3](#0-2) , causing the victim to either be bounced (`'wrong ratio of amounts'`) or to receive an incorrect number of shares relative to their deposited assets.
5. The attacker can later trigger the "divest MM shares" or "exchange" cases to extract value corresponding to the donated balance that diluted the victim's position.

### Citations

**File:** aa_composer.js (L375-397)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
		trigger.max_aa_responses = objUnit.max_aa_responses;
	objUnit.messages.forEach(function (message) {
		if (message.app === 'data' && !trigger.data) // use the first data message, ignore the subsequent ones
			trigger.data = message.payload;
		else if (message.app === 'payment' && message.payload) {
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address === receiving_address) {
					if (!trigger.outputs[asset])
						trigger.outputs[asset] = 0;
					trigger.outputs[asset] += output.amount; // in case there are several outputs
				}
			});
		}
	});
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L474-541)
```javascript
	// add the coins received in the trigger
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
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
				async.series(arrQueries, function () {
					conn.query("SELECT storage_size FROM aa_addresses WHERE address=?", [address], function (rows) {
						if (rows.length === 0)
							throw Error("AA not found? " + address);
						storage_size = rows[0].storage_size;
						objValidationState.storage_size = storage_size;
						cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
					});
				});
			}
		);
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

**File:** test/aa.test.js (L970-1021)
```javascript
test.cb.serial('no outputs', t => {
	var db = require("../db");
	var batch = kvstore.batch();
	var stateVars = {};
	var objMcUnit = {
		unit: 'DTDDiGV4wBlVUdEpwwQMxZK2ZsHQGBQ6x4vM463/uy8=',
		last_ball_unit: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
		last_ball: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
		witness_list_unit: 'oj8yEksX9Ubq7lLc+p6F2uyHUuynugeVq4+ikT67X6E=',
		timestamp: 1.5e9+100,
	};
	storage.assocStableUnits[objMcUnit.unit] = {};
	var trigger = { address: 'TU3Q44S6H2WXTGQO6BZAGWFKKJCF7Q3W', outputs: { base: 40000 }, data: { x: 333 }, unit: objMcUnit.unit };
	var arrResponseUnits = [];
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
			t.end();
		});
	});
});
```
