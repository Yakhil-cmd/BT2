## Title
Stale in-memory AA balance cache after partial rollback allows balance corruption on secondary-AA bounce - (File: aa_composer.js)

### Summary
The `revert()` function in `aa_composer.js`, which is invoked when a chain of secondary AA triggers fails after state changes and balance updates have already been applied, issues `ROLLBACK TO SAVEPOINT initial_balances` to undo the AA balance changes in the database, but never resets the in-memory `objValidationState.assocBalances` cache to match the DB state that was just restored. This mirrors the root cause of CVE-2022-50303 (double release due to inconsistent state after a partially-failed operation): a resource's authoritative on-disk/DB state is rolled back, but the cached in-memory bookkeeping is left stale, and that stale state is subsequently trusted and reused by later code, corrupting accounting.

### Finding Description
`handleTrigger()` tracks per-address AA balances in `objValidationState.assocBalances`, populated in `updateInitialAABalances()` and mutated by `updateFinalAABalances()` as messages are executed [1](#0-0) . A `SAVEPOINT initial_balances` is created right after the initial (trigger-received) balance is computed [2](#0-1) .

When a secondary AA in a chain fails, `handleSecondaryTriggers()` calls `revert()` with the accumulated error [3](#0-2) . `revert()` clears in-memory `arrResponses`/`stateVars`, and issues `conn.query("ROLLBACK TO SAVEPOINT initial_balances", ...)` before finally calling `bounce(err)`: [4](#0-3) 

Crucially, `revert()` restores `stateVars` (`Object.keys(stateVars).forEach(... delete ...)`) but does **not** restore `objValidationState.assocBalances[address]` to the values that were correct at the savepoint. The DB balance is now rolled back to the pre-spend state, but the in-memory `assocBalances` object still reflects all the deltas from `updateFinalAABalances()` calls made during the now-reverted secondary trigger chain (spent outputs, changed amounts, etc.).

After the rollback, `bounce(err)` proceeds to build a bounce payment and calls `sendUnit(messages)` again [5](#0-4) . `sendUnit()` eventually calls `updateFinalAABalances(arrConsumedOutputs, objUnit, cb)` a second time on the very same `objValidationState.assocBalances[address]` object [6](#0-5) , applying new deltas on top of the stale (pre-rollback) balances rather than on top of the actual, just-restored DB balances: [7](#0-6) 

Since subsequent SQL updates in `updateFinalAABalances` are relative `UPDATE aa_balances SET balance=balance+?` statements against the real (rolled-back) DB row, the SQL side stays numerically correct for that single call, but the **JS-side `objValidationState.assocBalances` cache used for further formula evaluation, guarding against negative balances, and validation** (`bounce()` fee checks, `sendDummyUnit` balance checks in air-gapped estimation mode, and later formula reads via `balance[...]`) is left holding amounts that double-count balance changes that were already discarded by the ROLLBACK TO SAVEPOINT. This is analogous to the kernel bug where a resource's reference/ownership bookkeeping (pasid) was left in a stale state after a failure path, leading a second, independent code path to trust that stale bookkeeping and free/use the same resource incorrectly.

### Impact Explanation
Because AA `assocBalances` values gate real payments the AA sends (`trigger_opts.assocBalances[address][asset] -= output.amount` in `sendDummyUnit`, and read via the `balance[asset]` formula operator during subsequent secondary triggers or the bounce message construction), a stale, artificially-inflated in-memory balance can let an AA author-crafted trigger cause the AA to construct/allow spends that its true database balance does not support, or cause balance bookkeeping used by later formula/getter evaluation to diverge from actual on-chain state (`checkBalances()` is exactly the sanity-check function designed to catch this class of divergence). This is a fund-accounting integrity issue reachable purely by an unprivileged AA trigger sender constructing a trigger chain that causes a secondary AA in the call chain to fail after balance-affecting messages have executed, forcing the revert/bounce path.

### Likelihood Explanation
Triggering `revert()` only requires posting a unit that invokes a primary AA whose secondary-trigger chain includes at least one AA that bounces/fails after an earlier AA in the chain already spent/received funds — a scenario fully reachable by any address posting a trigger unit and by AA authors composing multi-hop AA calls, no privileged network position or node compromise needed.

### Recommendation
In `revert()`, snapshot `objValidationState.assocBalances` (and any other spend-tracking state such as `byte_balance`/`storage_size`) before mutation begins (similar to `originalStateVars`), and restore that snapshot when performing `ROLLBACK TO SAVEPOINT initial_balances`, so the in-memory balance cache is guaranteed to match the just-restored DB state before `bounce()` re-enters `sendUnit()`/`updateFinalAABalances()`. This mirrors the kernel fix's approach of only setting/trusting shared state at the exact point where its ownership/consistency is guaranteed.

### Proof of Concept
1. Define AA `X` that on trigger sends `total-100` bytes to secondary AA `Y` (spending its balance) and includes a further conditional message.
2. Define AA `Y` that, depending on trigger data or a getter call, bounces (fails) after AA `X`'s balance mutation via `updateFinalAABalances` has already executed for the amount sent to `Y`.
3. Post a unit that triggers `X`, causing: `X` spends funds -> `updateFinalAABalances` mutates `objValidationState.assocBalances[X]` -> secondary call to `Y` fails -> `handleSecondaryTriggers` calls `revert()` -> DB balance for `X` is rolled back to savepoint, but `assocBalances[X]` in memory is not reset -> `bounce()` builds a bounce unit and calls `sendUnit()` again -> `updateFinalAABalances` runs a second time on the stale cache.
4. Observe (e.g., via `aa_composer.checkBalances()` at aa_composer.js:1954 or by inspecting `aa_balances` vs. actual spendable outputs) that the DB balance and the AA's effective spendable/reported balance for subsequent triggers diverge, or that a follow-up trigger relying on `balance[asset]` sees an incorrect, inflated value relative to true on-chain funds.

### Citations

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

**File:** aa_composer.js (L543-587)
```javascript
	function updateFinalAABalances(arrConsumedOutputs, objUnit, cb) {
		if (trigger_opts.bAir)
			throw Error("updateFinalAABalances shouldn't be called with bAir");
		var assocDeltas = {};
		var arrNewAssets = [];
		arrConsumedOutputs.forEach(function (output) {
			if (!assocDeltas[output.asset])
				assocDeltas[output.asset] = 0;
			assocDeltas[output.asset] -= output.amount;
			// this might happen if there is another pending invocation of our AA that created the outputs we are spending now
			if (!objValidationState.assocBalances[address][output.asset])
				arrNewAssets.push(output.asset);
		});
		objUnit.messages.forEach(function (message) {
			if (message.app !== 'payment')
				return;
			var payload = message.payload;
			var asset = payload.asset || 'base';
			payload.outputs.forEach(function (output) {
				if (output.address !== address)
					return;
				if (!assocDeltas[asset]) { // it can happen if the asset was issued by AA
					assocDeltas[asset] = 0;
					arrNewAssets.push(asset);
				}
				assocDeltas[asset] += output.amount;
			});
		});
		var arrQueries = [];
		if (arrNewAssets.length > 0) {
			var arrValues = arrNewAssets.map(function (asset) { return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", 0)"; });
			conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
		}
		for (var asset in assocDeltas) {
			if (assocDeltas[asset]) {
				conn.addQuery(arrQueries, "UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=?", [assocDeltas[asset], address, asset]);
				if (!objValidationState.assocBalances[address][asset])
					objValidationState.assocBalances[address][asset] = 0;
				objValidationState.assocBalances[address][asset] += assocDeltas[asset];
			}
		}
		if (assocDeltas.base)
			byte_balance += assocDeltas.base;
		async.series(arrQueries, cb);
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

**File:** aa_composer.js (L1405-1411)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```

**File:** aa_composer.js (L1743-1749)
```javascript
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
```

**File:** aa_composer.js (L1759-1798)
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
		/*
		conn.query("ROLLBACK", function () {
			conn.query("BEGIN", function () {
				// initial AA balances were rolled back, we have to add them again
				if (!fPrepare)
					fPrepare = function (cb) { cb(); };
				fPrepare(function () {
					updateInitialAABalances(function () {
						console.log('done revert: ' + err);
						bounce(err);
					});
				});
			});
		});*/
	}
```
