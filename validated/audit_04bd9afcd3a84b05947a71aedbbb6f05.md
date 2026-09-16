### Title
Front-running of balance-gated owner reconfiguration logic in Autonomous Agents due to deterministic level-based trigger ordering - (File: `aa_composer.js`, `formula/evaluation.js`)

### Summary
Any Autonomous Agent (AA) that gates an owner-only "reconfiguration" branch on a live `balance[asset]` (or a state variable derived from it) can be permanently DoS'd/griefed the same way `VaultBooster.setBoost()` was: an unprivileged attacker sends a tiny trigger to the AA that changes the AA's balance/state just before the legitimate owner trigger is processed, causing the owner's condition to evaluate falsely (or its `bounce()` guard to fire) every single main-chain-index (MCI) round, indefinitely blocking the reconfiguration.

### Finding Description
Inside an AA, `balance[asset]` and state variables are read live from `objValidationState.assocBalances`, which is populated per-trigger by `readBalance()`/`updateInitialAABalances()` [1](#0-0) [2](#0-1) . Many published AA patterns (e.g. the AMM sample) place ownership/config-gating logic directly on top of this mutable balance, exactly mirroring the vulnerable `_initialAvailable > balance` check in `VaultBooster.setBoost()`:

```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
``` [3](#0-2) 

Multiple primary triggers addressed to the same AA can exist unconfirmed at the same time. When the enclosing MCI is finally marked stable, all pending triggers to AAs at that MCI are collected and executed in a **fully deterministic order**:

```
"SELECT DISTINCT address, definition, units.unit, units.level ...
 ORDER BY units.level, units.unit, address", // deterministic order
``` [4](#0-3) 

and later re-fetched/executed with the same ordering key:
```
"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
 FROM aa_triggers ...
 ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
``` [5](#0-4) 

`level` is a DAG property of the trigger-carrying unit that the author controls by choosing which parent units to build on — an attacker who observes the owner's pending (not-yet-stable) reconfiguration unit in the DAG can craft a low-level competing unit (e.g., referencing fewer/older parents) that is guaranteed to be scheduled and executed **before** the owner's unit within the same MCI. This is the DAG analogue of "front-running a pending transaction" in the report: the attacker's trigger runs first, mutates `balance[asset]`/state, and the owner's subsequent trigger then fails its balance-based guard and is bounced by `bounce()` [6](#0-5) , with the response unit rolled back via `revert()` [7](#0-6) . Because the same griefing unit can be resubmitted every round for negligible fees, the attacker can indefinitely deny the reconfiguration, exactly as in the `VaultBooster` finding.

### Impact Explanation
If an AA's safety-critical parameters (fee rates, price bounds, pausing, liquidity ratios, boost/emission rates, etc.) are guarded by a live-balance condition, an attacker can permanently block the owner from applying an update. Depending on the AA's design this can:
- freeze the AA in a stale/exploitable configuration, enabling continued value extraction (e.g., a mispriced AMM ratio, as in `uniswap_like_market_maker.oscript`) — an "AA fund loss" scenario, or
- prevent a defensive pause/parameter fix from ever landing, indefinitely — an "AA freezing" scenario.

This matches the accepted Medium-severity classification of the original finding (griefing/DoS on configuration, not direct theft).

### Likelihood Explanation
Likelihood is High for any AA that follows this common oscript pattern (balance/state-gated owner branch), because:
- Triggers to an AA are visible in the unstable DAG before the MCI stabilizes, giving the attacker a clear window to react.
- Building a lower-level unit costs only the minimum trigger fee (a few hundred/thousand bytes) and requires no special privilege.
- The attack can be repeated every MCI at negligible cost, so it scales to "as long as needed", identical to the original report's observation that even 1-wei-sized griefing transactions suffice.

### Recommendation
- Avoid gating privileged/owner-only branches on live, attacker-influenceable `balance[asset]` values; instead snapshot required balances into a state variable set once (e.g., at AA definition/deployment time) or use values that cannot be altered by third-party triggers between blocks.
- Where a balance check is unavoidable, design the condition to tolerate additive griefing (e.g., check `balance >= required` rather than an exact/strict inequality that any inbound payment can flip), or add a "pause"/"maintenance mode" path reachable by the owner regardless of balance state, similar to the report's own recommended mitigation.
- AA authors should be warned (documentation/linters) that `balance[...]` and other externally-influenceable reads are not safe as the sole gate for privileged state-transition logic given oscript's trigger-ordering semantics.

### Proof of Concept
1. Deploy an AA whose `messages.cases` contains an owner-only branch such as:
```
if: "{ trigger.address == $owner AND balance[$asset] == var['expected_balance'] }"
```
(mirroring `VaultBooster.setBoost()`'s `_initialAvailable > balance` check).
2. Owner composes and broadcasts a reconfiguration-trigger unit `U_owner` (unstable, visible in the DAG, not yet included in a stable MCI).
3. Attacker, seeing `U_owner` in the DAG, composes a minimal-value trigger unit `U_attacker` to the same AA, choosing parents so that `level(U_attacker) < level(U_owner)`.
4. Both units become included in the same MCI. When the MCI stabilizes, `aa_composer.handleAATriggers()` selects and executes triggers `ORDER BY ... level ...` [5](#0-4) , so `U_attacker` runs first and mutates `balance[$asset]`/`var['expected_balance']`.
5. `U_owner`'s trigger then runs, its `if` condition evaluates false (or the analogous `bounce()` branch fires), and the reconfiguration is rejected via `bounce()`/`revert()` [6](#0-5) [7](#0-6) .
6. Attacker repeats step 3 every subsequent MCI, permanently preventing the owner's reconfiguration from ever succeeding.

### Citations

**File:** formula/evaluation.js (L1510-1527)
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
```

**File:** aa_composer.js (L63-68)
```javascript
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
```

**File:** aa_composer.js (L474-490)
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

**File:** test/samples/uniswap_like_market_maker.oscript (L34-47)
```text
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

**File:** main_chain.js (L1691-1723)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
		);
	}
```
