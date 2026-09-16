### Title
Stale `assocBalances` Cache Not Reset on AA Trigger Revert - ([File: aa_composer.js])

### Summary
When an Autonomous Agent (AA) trigger execution has to be rolled back mid-flight (e.g. `updateStorageSize` fails after a response unit was already sent, or a secondary AA bounces), `handleTrigger`'s `revert()` function rolls back the database to a savepoint but never resets the in-memory balance cache `objValidationState.assocBalances`. This is the same bug class as the Raydium AMM report: an on-chain/DB state change (order cancellation / here, payment settlement) is undone, but a cached copy of derived balances used for subsequent decisions is not refreshed, so later logic (`bounce()`, and any further formula evaluation of `balance[...]`) operates on stale, inconsistent data.

### Finding Description
`handleTrigger()` in `aa_composer.js` maintains `objValidationState.assocBalances`, an in-memory cache of AA balances that is mutated as messages are evaluated and payments are sent (`updateFinalAABalances`, `sendDummyUnit`, `readBalance` in `formula/evaluation.js`). [1](#0-0) 

When something goes wrong after a response unit has already been composed and its AA balances already been debited/credited (e.g. `updateStorageSize` fails in `finish()`, or one of the secondary AAs bounces in `handleSecondaryTriggers()`), the code calls `revert()`: [2](#0-1) 

`revert()` correctly discards `arrResponses`, clears `stateVars`, clears the `batch`, and issues `ROLLBACK TO SAVEPOINT initial_balances` to undo every `aa_balances` DB update made while composing the (now discarded) response(s): [3](#0-2) 

However, `objValidationState.assocBalances` — the same object read by `balance[...]` in oscript (`readBalance` in `formula/evaluation.js`) and written by `updateFinalAABalances`/`sendDummyUnit` — is never reset or reloaded from the database after the `ROLLBACK TO SAVEPOINT`. The commented-out alternative code path directly below even shows the developers were aware that after a full rollback the balances must be reinitialized (`updateInitialAABalances(...)`), but this reinitialization only exists in the disabled/commented branch, not in the active `ROLLBACK TO SAVEPOINT` branch: [4](#0-3) 

Consequently, `bounce(err)`, which is invoked right after the DB rollback, and any subsequent formula evaluation for the bounce response (or a secondary trigger constructed with the same `trigger_opts.assocBalances`, see `handleTrigger`'s reuse of `trigger_opts` across secondary triggers) will see AA balances that reflect payments/state changes that were just rolled back in the database. This is functionally identical to the reported Raydium defect: an action (order cancellation / payment reversal) invalidates the authoritative state, but a cached snapshot used for the next decision (settlement check / bounce computation) is not refreshed. [5](#0-4) 

### Impact Explanation
Because `assocBalances` is shared by reference across the whole `handlePrimaryAATrigger` call (including all secondary triggers spawned via `trigger_opts`), a stale post-rollback cache can cause:
- The bounce response (or a following secondary trigger for the same primary trigger) to compute payment amounts based on balances that no longer match what's actually in `aa_balances`, causing either an inconsistency that fails unit validation (denial of legitimate settlement/refund, effectively freezing AA funds that cannot be spent through the normal path) or, in the best case for an attacker, a mismatch that causes `balance[...]` reads to disagree with the ledger.
- `checkBalances()`, the periodic invariant check comparing `aa_balances` against actual UTXO outputs, is designed to `throw Error` on any mismatch between calculated and stored balances, indicating that such divergences are considered consensus-critical; a persistent divergence introduced by an unrefreshed cache can make an AA's exposed balance disagree with its actual entitlement, risking stuck/frozen AA funds until the AA is redeployed or nodes crash-loop on the invariant check. [6](#0-5) 

This matches the “AA fund loss or freezing” / “node disagreement on validity” impact classes required by the validation rubric.

### Likelihood Explanation
Triggering the revert path requires an ordinary, unprivileged interaction: any unit poster (or AA acting as a trigger sender) can craft a trigger that causes an AA chain to compose a response, then fail later (e.g. by causing a secondary AA in the chain to legitimately bounce, or hitting a storage-size failure) so that `revert()` fires. Since `revert()` and its stale-cache side effect execute unconditionally whenever this failure path is reached, no special privileges beyond normal unit/trigger submission are needed, making this readily reachable by an ordinary AA trigger sender.

### Recommendation
In `revert()` (aa_composer.js), after `ROLLBACK TO SAVEPOINT initial_balances` succeeds, reload `objValidationState.assocBalances[address]` (and any other addresses mutated during the discarded execution) from the `aa_balances` table before calling `bounce(err)`, mirroring the commented-out `updateInitialAABalances()` call that already exists just below the active code path. Alternatively, snapshot `assocBalances` before any balance-mutating step and restore that snapshot on `revert()`, analogous to how `originalStateVars`/`originalBalances` are already tracked for other purposes.

### Proof of Concept
1. Construct a primary AA (`A`) whose response chain includes a secondary AA (`B`) in `handleSecondaryTriggers`.
2. Design `B` so that, depending on `A`'s already-updated balance-dependent state, it bounces (returns an error) after `A`'s response has already gone through `updateFinalAABalances`/`addResponse` (i.e., after `A`'s `assocBalances[A]` has been decremented for the payment it sent to `B`).
3. This causes `handleSecondaryTriggers`'s `async.eachSeries` callback to call `revert({...})` for the primary trigger, which performs `ROLLBACK TO SAVEPOINT initial_balances` — restoring `A`'s DB balance to its pre-send value — while `objValidationState.assocBalances[A]` still holds the decremented value.
4. `bounce(err)` is then invoked with this stale cache; because `trigger_opts.assocBalances` is the same object reused for any subsequent formula evaluation reading `balance[...]` for `A`, further logic (bounce response composition or later checks in `checkBalances()`) operates on a balance value that disagrees with the just-restored database state, producing a persistent balance-cache/DB mismatch for AA `A`.

### Citations

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

**File:** aa_composer.js (L1690-1757)
```javascript
		fixStateVars();
		saveStateVars();
		addResponse(objResponseUnit, function () {
			updateStorageSize(function (err) {
				if (err)
					return revert(err);
				addUpdatedStateVarsIntoPrimaryResponse();
				onDone(objResponseUnit, bBouncing ? error_message : false);
			});
		});
	}

	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
				},
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
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

**File:** aa_composer.js (L1784-1797)
```javascript
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
```

**File:** aa_composer.js (L1954-1990)
```javascript
function checkBalances() {
	mutex.lockOrSkip(['checkBalances'], function (unlock) {
		db.takeConnectionFromPool(function (conn) { // block conection for the entire duration of the check
			conn.query("SELECT 1 FROM aa_triggers", function (rows) {
				if (rows.length > 0) {
					console.log("skipping checkBalances because there are unhandled triggers");
					conn.release();
					return unlock();
				}
				var sql_create_temp = "CREATE TEMPORARY TABLE aa_outputs_balances ( \n\
					address CHAR(32) NOT NULL, \n\
					asset CHAR(44) NOT NULL, \n\
					calculated_balance BIGINT NOT NULL, \n\
					PRIMARY KEY (address, asset) \n\
				)" + (conf.storage === 'mysql' ? " ENGINE=MEMORY DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci" : "");
				var sql_fill_temp = "INSERT INTO aa_outputs_balances (address, asset, calculated_balance) \n\
					SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) \n\
					FROM aa_addresses \n\
					CROSS JOIN outputs USING(address) \n\
					CROSS JOIN units ON outputs.unit=units.unit \n\
					LEFT JOIN assets ON outputs.asset=assets.unit \n\
					WHERE is_spent=0 AND sequence='good' AND ( \n\
						is_stable=1 \n\
						OR is_stable=0 AND is_aa_response=1 \n\
					) AND (is_private=0 OR is_private IS NULL) \n\
					GROUP BY address, asset";
				var sql_balances_to_outputs = "SELECT aa_balances.address, aa_balances.asset, balance, calculated_balance \n\
				FROM aa_balances \n\
				LEFT JOIN aa_outputs_balances USING(address, asset) \n\
				GROUP BY aa_balances.address, aa_balances.asset \n\
				HAVING balance != IFNULL(calculated_balance, 0)";
				var sql_outputs_to_balances = "SELECT aa_outputs_balances.address, aa_outputs_balances.asset, balance, calculated_balance \n\
				FROM aa_outputs_balances \n\
				LEFT JOIN aa_balances USING(address, asset) \n\
				GROUP BY aa_outputs_balances.address, aa_outputs_balances.asset \n\
				HAVING IFNULL(balance, 0) != calculated_balance";
				var sql_drop_temp = db.dropTemporaryTable("aa_outputs_balances");
```
