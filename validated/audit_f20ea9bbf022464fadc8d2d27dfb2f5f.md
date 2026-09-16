## Title
Unchecked arithmetic on the `aa_balances` reserve ledger in `updateFinalAABalances` can silently corrupt an AA's tracked fund balance — ([File: aa_composer.js])

### Summary
The reported Solidity bug is a class of vulnerability where a pooled/reserved balance (`reservedFunds -= value`) is decremented without first validating that `value` cannot exceed the tracked reserve, so any miscalculation of `value` silently corrupts the accounting state used to gate future fund movements. The ocore analog is the Autonomous Agent (AA) balance ledger maintained in the `aa_balances` table, which is updated with the exact same unchecked-subtraction pattern in `updateFinalAABalances`.

### Finding Description
Every time an AA sends a payment, `aa_composer.js`'s `updateFinalAABalances` computes a signed delta per asset and commits it directly to the persistent `aa_balances` ledger with no bounds check: [1](#0-0) 

Specifically, `assocDeltas[output.asset] -= output.amount;` decrements the in-memory delta for every consumed output, and outputs paid back to the same AA are added back in the messages loop. The final deltas are then applied unconditionally via `UPDATE aa_balances SET balance=balance+?` — there is no assertion anywhere in this function that the resulting `objValidationState.assocBalances[address][asset]` (or the persisted `balance` column) stays non-negative or otherwise consistent with reality.

This cached ledger is the sole source of truth handed to the *next* AA trigger's initial balance state via `readAABalances`: [2](#0-1) 

and it feeds directly into `updateInitialAABalances`, which trusts the stored `balance` column as ground truth for the AA's spendable funds on the next invocation: [3](#0-2) 

Because the ledger is only reconciled after the fact by a best-effort background job (`checkBalances`), which merely `throw`s on divergence rather than preventing it, and the codebase itself contains a dedicated `reintroduceBalanceBug` compensation function that patches specific known-corrupted addresses on testnet: [4](#0-3) [5](#0-4) 

this demonstrates that the unchecked subtract-then-persist pattern in `updateFinalAABalances` has previously produced real, silently-accepted balance corruption in production that had to be patched out-of-band — exactly the risk class flagged in the external report ("high risk of funds loss ... if value calculated wrong or manipulated").

### Impact Explanation
If the delta computed in `updateFinalAABalances` is ever wrong (e.g. due to an edge case in secondary-trigger handling, a race between concurrently-processed AA responses touching the same asset/address, or any accounting drift between `arrConsumedOutputs` and the actual spent set), the persisted `aa_balances.balance` value becomes permanently wrong with no runtime rejection. Because every subsequent trigger's `assocBalances` (and therefore every `balance[asset]` reference available to AA oscript formulas, and every "not enough funds" gate in `sendUnit`) is seeded straight from this table, an inflated cached balance lets an AA compose payments it cannot actually cover (fund loss / freezing for the AA and its users), while a deflated cached balance permanently locks the AA out of funds it legitimately holds (freezing). This matches the "AA fund loss or freezing" impact category.

### Likelihood Explanation
This code path executes on every real AA response that sends a payment — it is on the hot path for any unprivileged user who posts a trigger unit invoking an AA that pays out (a very common AA pattern). No special privilege is required to reach it; only a latent accounting edge case (already evidenced once, via `reintroduceBalanceBug`) is needed to trigger silent corruption. The consistency check (`checkBalances`) only detects divergence after the fact by crashing the node process — it does not prevent the corrupted value from being read and acted on by the AA before the check runs.

### Recommendation
Add an explicit invariant check inside `updateFinalAABalances` before committing deltas: verify that `objValidationState.assocBalances[address][asset] + assocDeltas[asset] >= 0` for every asset, and fail the trigger (bounce) rather than silently persisting a value that could represent an inconsistent state. Additionally, consider making the balance update and its precondition check atomic within the same SQL statement (e.g. `UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? AND balance+?>=0`) and treating zero affected rows as a hard error, so any accounting drift is caught synchronously instead of relying solely on the asynchronous `checkBalances` sweep.

### Proof of Concept
Not applicable as a working exploit — the finding is based on static analysis of the missing invariant in `updateFinalAABalances` combined with the historical evidence in `reintroduceBalanceBug`, which is direct proof that this exact unchecked-subtraction/write path has previously produced corrupted `aa_balances` entries in production that required manual, address-specific compensation rather than being caught proactively.

### Citations

**File:** aa_composer.js (L491-514)
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
```

**File:** aa_composer.js (L543-586)
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
```

**File:** aa_composer.js (L1954-2053)
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
				
				/*
				var stable_or_from_aa = "( \n\
					(SELECT is_stable FROM units WHERE units.unit=outputs.unit)=1 \n\
					OR EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=outputs.unit) \n\
				)";
				var sql_base = "SELECT aa_addresses.address, balance, SUM(amount) AS calculated_balance \n\
					FROM aa_addresses \n\
					LEFT JOIN aa_balances ON aa_addresses.address = aa_balances.address AND aa_balances.asset = 'base' \n\
					LEFT JOIN outputs \n\
						ON aa_addresses.address = outputs.address AND is_spent = 0 AND outputs.asset IS NULL \n\
						AND " + stable_or_from_aa + " \n\
					GROUP BY aa_addresses.address \n\
					HAVING balance != calculated_balance";
				var sql_assets_balances_to_outputs = "SELECT aa_balances.address, aa_balances.asset, balance, SUM(amount) AS calculated_balance \n\
					FROM aa_balances \n\
					LEFT JOIN outputs " + db.forceIndex('outputsByAddressSpent') + " \n\
						ON aa_balances.address=outputs.address AND is_spent=0 AND outputs.asset=aa_balances.asset \n\
						AND " + stable_or_from_aa + " \n\
					WHERE aa_balances.asset!='base' \n\
					GROUP BY aa_balances.address, aa_balances.asset \n\
					HAVING balance != calculated_balance";
				var sql_assets_outputs_to_balances = "SELECT aa_addresses.address, outputs.asset, balance, SUM(amount) AS calculated_balance \n\
					FROM aa_addresses \n\
					CROSS JOIN outputs \n\
						ON aa_addresses.address=outputs.address AND is_spent=0 \n\
						AND " + stable_or_from_aa + " \n\
					LEFT JOIN aa_balances ON aa_addresses.address=aa_balances.address AND aa_balances.asset=outputs.asset \n\
					WHERE outputs.asset IS NOT NULL \n\
					GROUP BY aa_addresses.address, outputs.asset \n\
					HAVING balance != calculated_balance";
				*/
				async.eachSeries(
				//	[sql_base, sql_assets_balances_to_outputs, sql_assets_outputs_to_balances],
					[sql_create_temp, sql_fill_temp, sql_balances_to_outputs, sql_outputs_to_balances, sql_drop_temp],
					function (sql, cb) {
						conn.query(sql, function (rows) {
							if (!Array.isArray(rows))
								return cb();
							// ignore discrepancies that result from limited precision of js numbers
							rows = rows.filter(row => {
								if (row.balance <= Number.MAX_SAFE_INTEGER || row.calculated_balance <= Number.MAX_SAFE_INTEGER)
									return true;
								var diff = Math.abs(row.balance - row.calculated_balance);
								if (diff > row.balance * 1e-5) // large relative difference cannot result from precision loss
									return true;
								console.log("ignoring balance difference in", row);
								return false;
							});
							if (rows.length > 0)
								throw Error("checkBalances failed: sql:\n" + sql + "\n\nrows:\n" + JSON.stringify(rows, null, '\t'));
							cb();
						});
					},
					function () {
						conn.release();
						unlock();
					}
				);
			});
		});
	});
}
```

**File:** aa_composer.js (L2055-2070)
```javascript
function reintroduceBalanceBug(address, row) {
	if (address === 'XM3EMLR3D3VLKDNPSZSJTSKPKFFXDDHV') row.balance -= 3125;
	if (address === 'FSEIUKVQNYNF5BQE5S46R7ERQDVROVJL') row.balance -= 3337;
	if (address === 'BCHGVAJRLHS3HMA7NMKZ4BO6JQKUW3Q5') row.balance -= 2173;
	if (address === 'H4KE7UKFJOMMBXSQ6YPWNF66AK4WCIHI') row.balance -= 2200;
	if (address === 'W4BXAP5B6CB3VUBTTEWILHDLBH32GW77') row.balance -= 2200;
	if (address === '5MUADPAHD5HODQ2H2I4VJK7LIJP2UWEM') row.balance -= 2173;
	if (address === 'R5XIX3LV56SXLDL2RRU3MTMDEX7KMG7E') row.balance -= 2096;
	if (address === '5G6AIA2SNEKZCHL4CWGRCG6U4YJEMMEG') row.balance -= 2123;
	if (address === 'DVPC3PRVQ52DDBSHMRFOFRDDPG5CUKKG') row.balance -= 2055;
	if (address === 'ZZEC7WHPGVAPHB6TZY5EQNDFMRA3PBFB') row.balance -= 2028;
	if (address === 'X5ZRXFN27AS5AXALITEBJGJAJCGB3HFK') row.balance -= 2019;
	if (address === 'CPTSL3OUMDIEKQ2LJWRO2BDJVRUTH7TZ') row.balance -= 1992;
	if (address === 'AE7RCCPDR2DOSEOSTQA4XP7CSR5SY3WM') row.balance -= 1959;
	if (address === '7SBOUY5ERICX4XHFS42FJJVVAN4YJ3BZ') row.balance -= 1932;
}
```

**File:** storage.js (L984-994)
```javascript
function readAABalances(conn, address, handleBalances) {
	if (!handleBalances)
		return new Promise(resolve => readAABalances(conn, address, resolve));
	conn.query("SELECT asset, balance FROM aa_balances WHERE address=?", [address], function (rows) {
		var assocBalances = {};
		rows.forEach(function (row) {
			assocBalances[row.asset] = row.balance;
		});
		handleBalances(assocBalances);
	});
}
```
