### Title
Coins sent to an Autonomous Agent via a private payment are excluded from `aa_balances` and become permanently untracked - ([File: aa_composer.js])

### Summary
Ajna's issue is that assets transferred into the pool outside of the tracked deposit/collateral path (rebases, donations) are never reflected in the pool's internal accounting and are effectively lost. The analogous ocore issue is that bytes/assets sent to an Autonomous Agent (AA) address as part of a **private payment** are excluded from `aa_balances` bookkeeping by design, so the AA's oscript logic (`balance[...]`, `trigger.outputs`) never learns that it received them, permanently freezing those funds from the AA's own accounting/spending logic even though the outputs physically exist at the AA's address.

### Finding Description
Every code path that establishes or verifies an AA's tracked balance explicitly filters out private outputs:

- When an AA is first defined, its initial balance is seeded only from public payments: [1](#0-0) 
the `WHERE address=? AND is_spent=0 AND sequence='good' AND ... AND (is_private=0 OR is_private IS NULL)` clause skips any private output ever sent to the (not-yet-defined) AA address.

- The periodic consistency check `checkBalances()` reconciles `aa_balances` against the `outputs` table using the same exclusion: [2](#0-1) 
so a private output sitting at an AA address is *not* expected to be reflected in `aa_balances`, confirming this is the intended (but unsafe) behavior rather than an incidental bug.

- At runtime, whenever an AA is triggered, its balance is incrementally maintained in the `aa_balances` table (`updateInitialAABalances` / `updateFinalAABalances`), which is populated purely from `trigger.outputs` (derived from public payment messages of the triggering unit) and from public payment messages the AA itself sends/receives: [3](#0-2) [4](#0-3) 

- oscript's `balance[asset]` primitive, which AA authors use to decide what to do with received funds, reads exclusively from this same `aa_balances` table / in-memory mirror, never from the raw `outputs` table: [5](#0-4) 

Because a private payment to an AA address (i) never becomes an AA trigger with recognized `trigger.outputs` for that asset, and (ii) is never inserted into `aa_balances`, the AA's own logic has no way to know these funds exist, mirroring the Ajna scenario where value enters the contract's custody but is invisible to the contract's internal ledger.

### Impact Explanation
An unprivileged private-payment counterparty can send bytes or a private asset to any live AA address. The AA will never see this amount in `trigger.outputs`, never credit it to `aa_balances`, and its oscript code (which computes payouts, caps, or send-all amounts based on `balance[...]`) can never account for or intentionally forward it. The funds are stuck at the AA address, permanently outside the AA's own tracked economy - a fund-freezing condition reachable by any counterparty capable of constructing a private payment to a known AA address, requiring no special privilege.

### Likelihood Explanation
Any user who can compose a private payment (a fully-supported ocore feature) to an AA address can trigger this condition; no special role, timing, or race condition is required, making it straightforward to reproduce for any AA that accepts payments.

### Recommendation
Either (a) reject/refuse private payments sent to AA addresses at validation time so the funds are never accepted into an unrecoverable state, or (b) extend the trigger/balance-accounting pipeline (`insertAADefinitions`, `updateInitialAABalances`, `checkBalances`) to include private outputs received by AA addresses, ensuring `aa_balances` and oscript's `balance[...]` reflect the AA's true custody of funds regardless of payment privacy.

### Proof of Concept
1. Define an AA at address `A`.
2. Have an unprivileged wallet send a private payment (private asset or private-payment chain) with `A` as the recipient output address.
3. Observe that the payment is accepted and the output becomes part of `outputs` for address `A`, but:
   - `aa_triggers`/trigger construction ignores it (no public payment message referencing the AA as recipient in a way that is treated as `trigger.outputs`),
   - `aa_balances` for address `A` is never incremented for this asset (per the `is_private=0 OR is_private IS NULL` filters in `storage.js` and `aa_composer.js`),
   - `formula/evaluation.js`'s `balance[asset]` for `A` continues to report the pre-transfer amount.
4. The AA can never programmatically detect or spend these funds through its normal oscript logic tied to `balance[...]`, leaving them stranded.

### Citations

**File:** storage.js (L954-961)
```javascript
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
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

**File:** aa_composer.js (L1969-1979)
```javascript
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
