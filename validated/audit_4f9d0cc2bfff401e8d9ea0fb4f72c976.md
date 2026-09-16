## Analysis: Unbounded `aa_balances` Array Causes AA Processing DoS

### Title
Unbounded, permissionless growth of the `aa_balances` list per Autonomous Agent enables denial-of-service of AA trigger processing - (File: `aa_composer.js`)

### Summary
Any user can permissionlessly cause an Autonomous Agent (AA) address to accumulate an unbounded number of distinct asset balance rows, since every unique custom asset paid to the AA creates a new row in `aa_balances` keyed by `(address, asset)`. This list is read and iterated in full on *every subsequent trigger* sent to that AA, and iterated again in several other core code paths, mirroring the `poolRewards` bug class: a permissionless, unbounded array that critical functions must loop over.

### Finding Description
`aa_balances` has primary key `(address, asset)` [1](#0-0) . A new row is inserted whenever an AA receives an output in a previously-unseen asset:

`updateInitialAABalances()` in `aa_composer.js` selects **all** existing balance rows for the AA and loops over them (`rows.forEach`) on every trigger, then inserts any newly-seen asset as an additional permanent row: [2](#0-1) 

Since custom assets can be freely defined and paid to any address by any unprivileged user (asset issuance and a payment to the AA are ordinary, unprivileged unit operations), an attacker can define many distinct assets and send tiny/dust amounts of each to a target AA. Each such payment/trigger permanently grows `aa_balances` for that AA — the row count is fully attacker-controlled and unbounded, exactly like the `poolRewards[id]` array in the external report growing unbounded via permissionless reward-token addition.

This growing collection is subsequently iterated in multiple critical, unprivileged-reachable code paths:
- `updateInitialAABalances()` — executed at the start of **every** future trigger to the AA, does `SELECT asset, balance FROM aa_balances WHERE address=?` and loops over all rows [3](#0-2) .
- `sendDummyUnit()` — iterates the full in-memory `trigger_opts.assocBalances[address]` object (populated from the same unbounded set) to compute `arrAssetsWithNegativeBalances` on every AA response [4](#0-3) .
- `checkBalances()` — a global consistency check that joins `aa_balances` against `outputs`/`units` for every AA address [5](#0-4) .
- `readAABalances()` — used to serve `light/get_aa_balances` responses and other balance-reading code, returning/looping the full unbounded asset set [6](#0-5) .

Unlike `foreach`/`map`/`filter`/`reduce` in oscript formulas, which require an explicit, checked `count` bound [7](#0-6) , the `aa_balances` iteration inside `aa_composer.js` has **no cap** on the number of distinct assets an AA can accumulate, and this cost is paid on every single future trigger sent to the AA — by any innocent user trying to interact with it.

### Impact Explanation
Because `updateInitialAABalances()` runs unconditionally at the start of trigger handling for every future primary and secondary trigger, an attacker can permanently inflate the per-trigger processing cost of any target AA by spamming it with payments of many distinct low-cost custom assets. As the number of distinct assets grows without bound, the cost (DB row scan, JS-side array diffing, and object iteration in `sendDummyUnit`) grows linearly and permanently for that AA, degrading every legitimate user's ability to interact with it and, in the limit, making it impractical for the AA to process triggers at all — freezing funds legitimately held or expected by users of that AA. This is deterministic and affects every node identically, so it does not cause consensus divergence, but it does create a practical denial-of-service of the AA's core functionality that can freeze user funds routed through it, directly analogous to the reported `poolRewards` DoS on `updateUserState`/`notifyBalanceChange`/`claimAll`.

### Likelihood Explanation
The cost of the attack is limited to issuing custom assets and sending small payments to the target AA — both are ordinary, permissionless, unprivileged operations available to any unit poster. No special permissions, timing, or race conditions are required, and the effect (extra `aa_balances` rows) is permanent and cannot be reversed by the AA or its users, making the likelihood high for any popular/high-value AA that an attacker wants to disrupt.

### Recommendation
Cap the number of distinct assets that can be tracked in `aa_balances` per AA address (e.g., reject/ignore payments in new assets beyond a maximum count, or require an allow-list/registration step analogous to the `poolRewards` allowlist fix), and avoid iterating the full `aa_balances` set on every trigger when only the assets referenced in the current trigger/response are needed.

### Proof of Concept
1. Attacker defines `N` distinct custom assets (ordinary `asset` message, unprivileged issuance).
2. Attacker sends a small payment of each asset to victim AA address `X`, one trigger per asset (or batched in fewer triggers), so `aa_balances` accumulates `N` rows for `X` via the INSERT path in `updateInitialAABalances()` [8](#0-7) .
3. Any subsequent legitimate trigger to `X` now must execute `SELECT asset, balance FROM aa_balances WHERE address=?` and iterate all `N` rows in `updateInitialAABalances()`, and iterate the resulting `N`-sized object again in `sendDummyUnit()`'s negative-balance check [4](#0-3) , increasing processing time/cost for every future user of `X` without bound as the attacker repeats step 1–2.

### Citations

**File:** initial-db/byteball-mysql.sql (L818-826)
```sql
CREATE TABLE aa_balances (
	address CHAR(32) NOT NULL,
	asset CHAR(44) NOT NULL, -- 'base' for bytes (NULL would not work for uniqueness of primary key)
	balance BIGINT NOT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (address, asset),
	FOREIGN KEY (address) REFERENCES aa_addresses(address)
	-- FOREIGN KEY (asset) REFERENCES assets(unit)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
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

**File:** aa_composer.js (L979-982)
```javascript
			let arrAssetsWithNegativeBalances = [];
			for (let asset in trigger_opts.assocBalances[address])
				if (asset !== 'base' && trigger_opts.assocBalances[address][asset] < 0)
					arrAssetsWithNegativeBalances.push(asset);
```

**File:** aa_composer.js (L1963-1989)
```javascript
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

**File:** formula/evaluation.js (L2359-2373)
```javascript
					evaluate(count_expr, function (count) {
						if (fatal_error)
							return cb(false);
						if (!Decimal.isDecimal(count))
							return setFatalError("count is not a number: " + count, { arr }, false, cb);
						count = count.toNumber();
						if (!ValidationUtils.isNonnegativeInteger(count))
							return setFatalError("count is not nonnegative integer: " + count, { arr }, false, cb);
						evaluateFunctionExpression(func_expr, arr, funcInfo => {
							if (fatal_error)
								return cb(false);
							var bArray = Array.isArray(res.obj);
							var arrElements = bArray ? res.obj : Object.keys(res.obj).sort();
							if (arrElements.length > count)
								return setFatalError("found " + arrElements.length + " elements in object, only up to " + count + " allowed", { arr }, false, cb);
```
