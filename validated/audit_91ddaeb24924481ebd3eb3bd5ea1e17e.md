### Title
Unbounded per-address asset-balance iteration in AA trigger handling can be used to degrade/stall unit stabilization on demand - (File: aa_composer.js)

### Summary
`handleTrigger()` in `aa_composer.js` calls `updateInitialAABalances()`, which — for every trigger sent to an Autonomous Agent — performs an unbounded `SELECT asset, balance FROM aa_balances WHERE address=?` query and then iterates the full result set with `rows.forEach(...)`. This runs synchronously and unconditionally as part of MCI stabilization (the framework-level, unmetered processing every full node performs, analogous to `BeginBlock`), before any oscript formula (and its gas/complexity metering) is ever evaluated. An attacker can cheaply grow `aa_balances` for a victim AA address to an arbitrary number of distinct asset rows by repeatedly sending it tiny payments in self-issued assets across many low-cost units/blocks. Once inflated, every subsequent trigger sent by anyone to that AA forces every stabilizing full node to iterate over the entire, attacker-controlled row set, causing the per-trigger processing cost to scale linearly (unbounded) with attacker-chosen input, without a matching fee or gas charge.

### Finding Description
When a unit becomes stable and contains payments to an AA address, `main_chain.js`'s `handleAATriggers()` (called from `stabilizeMci`/`markMcIndexStable`) inserts an `aa_triggers` row and then calls `aa_composer.handleAATriggers()`, which processes every queued trigger synchronously via `handlePrimaryAATrigger()` → `handleTrigger()`. [1](#0-0) [2](#0-1) 

Inside `handleTrigger()`, before any formula/oscript evaluation (and therefore before any complexity/op-cost metering applies), `updateInitialAABalances()` loads **all** rows ever recorded for the AA's address from `aa_balances` and iterates them to update `objValidationState.assocBalances`: [3](#0-2) 

There is no limit anywhere on the number of distinct assets that can accumulate for a given address in `aa_balances`. New rows are added on-the-fly whenever a trigger contains a previously-unseen asset for that address: [4](#0-3) 

An attacker (an ordinary, unprivileged asset issuer / unit poster) can:
1. Cheaply define many distinct assets (`case "asset"` payload) — each is an ordinary unprivileged unit.
2. Send tiny payments in each of these assets to the address of any existing AA over successive units/blocks (the same low-cost, multi-block spam pattern used in the referenced report).

Each such payment causes `aa_addresses`/`outputs` join logic in `handleAATriggers()` (`main_chain.js:1691-1723`) to recognize the AA as triggered (any payment output to an `aa_addresses.address` triggers it), which inserts a new `aa_balances` row for the new asset via `updateInitialAABalances`. Over time this grows `aa_balances` for the target address to thousands of rows at negligible cost.

From that point on, **every** subsequent trigger sent to that AA by anyone — not just the attacker — forces every full node, during the unmetered stabilization critical path, to run the `SELECT ... WHERE address=?` query and `rows.forEach` over the entire accumulated row set, scaling the per-trigger processing time with the number of distinct assets the attacker chose to plant. This work happens on the single JS event loop that also handles unit validation, joint saving, and MC stabilization for the whole node.

### Impact Explanation
Because this iteration occurs in the framework code that runs during MCI stabilization for every full node — a code path outside of oscript's per-operation gas/complexity metering — an attacker can inflate the processing time of any trigger sent to a popular AA (e.g., a DEX, oracle, or otherwise widely used AA) for a cost far below the resulting resource consumption. This degrades block/MCI processing throughput on all full nodes and can be used to selectively stall processing of a targeted AA's triggers (and, by extending the stabilization critical section, delay confirmation of unrelated units), which corresponds to "a network unable to confirm new units in a timely manner." This matches the reported bug class of unmetered, attacker-inflatable balance iteration in a consensus-adjacent critical path.

### Likelihood Explanation
Any unprivileged party can issue new assets and send payments to any AA's address; no special permissions, private keys, or node/peer compromise are required. The cost of planting N distinct-asset rows is proportional to N small transaction fees, while the resulting per-trigger cost imposed on every full node scales with N indefinitely, since no cap exists on distinct assets per address in `aa_balances`. This makes the attack economical and repeatable at will.

### Recommendation
- Cap the number of distinct assets tracked per AA address in `aa_balances` (reject/charge extra for excess), or
- Charge a scaling fee (e.g., proportional to `COUNT(DISTINCT asset) FROM aa_balances WHERE address=?`) for triggers that would introduce a new asset balance for an address, similar to how storage size and bounce fees are already charged, or
- Avoid loading the full `aa_balances` row set for the address on every trigger; instead read/update balances lazily only for the assets referenced by the incoming trigger, falling back to per-asset point queries as `formula/evaluation.js`'s `readBalance()` already does for on-demand balance reads. [5](#0-4) 

### Proof of Concept
1. Deploy or pick any existing AA at address `AA1`.
2. Attacker defines N cheap assets `asset_1 … asset_N` (each a standalone `asset` message in its own unit).
3. Attacker sends N separate units over N different MCIs, each containing a 1-unit payment of a distinct asset to `AA1`'s address (this is treated as a primary AA trigger by `handleAATriggers()` in `main_chain.js:1691-1723`), causing N new rows to accumulate in `aa_balances` for `AA1` via `aa_composer.js:515-524`.
4. Once N is large, any user (including the attacker) sends a normal trigger to `AA1`.
5. On stabilization, `updateInitialAABalances()` (`aa_composer.js:491-514`) executes `SELECT asset, balance FROM aa_balances WHERE address=?`, returning all N rows, and `rows.forEach` processes all of them — the processing time of this single trigger (and the MCI-stabilization critical section holding it) scales with N, which the attacker fully controls, at a fraction of the cost imposed on the network's processing pipeline.

### Citations

**File:** main_chain.js (L1262-1286)
```javascript
// marks the MCI stable, executes triggers, and updates tps fees
async function stabilizeMci(mci) {
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const batch = kvstore.batch();
	const count_aa_triggers = await markMcIndexStable(conn, batch, mci);
	await util.promisify(batch.write.bind(batch))({ sync: true });
	await conn.query("COMMIT");
	conn.release();
	if (count_aa_triggers > 0) {
		console.log(`executing ${count_aa_triggers} AA triggers after stabilizing MCI ${mci}`);
		// every trigger takes its own db connection
		const aa_composer = require("./aa_composer.js");
		await aa_composer.handleAATriggers();
	}
	if (mci >= constants.v4UpgradeMci) {
		console.log(`updating tps fees after stabilizing MCI ${mci}`);
		// get a new connection to write tps fees
		const conn = await db.takeConnectionFromPool();
		await conn.query("BEGIN");
		await storage.updateTpsFees(conn, [mci]);
		await conn.query("COMMIT");
		conn.release();
	}
}
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

**File:** aa_composer.js (L515-524)
```javascript
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
