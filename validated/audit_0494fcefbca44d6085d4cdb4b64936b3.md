### Title
Unbounded growth of `aa_balances` rows per AA address allows a spam-created-asset DoS of that AA's trigger processing - (File: aa_composer.js)

### Summary
Any user can define a new asset (cheap, permissionless) and send a dust payment of that asset to any Autonomous Agent (AA) address. Every distinct asset ever received by an AA is inserted into `aa_balances` and is never pruned. On *every* subsequent trigger of that AA, the full, ever-growing set of `aa_balances` rows for the AA is read from the DB and iterated in JavaScript. There is no cap on the number of distinct assets an AA can accumulate, so an attacker can make this per-trigger work grow arbitrarily large over time, degrading (and eventually effectively freezing) the AA's ability to process legitimate triggers, analogous to the `assetsLen`/`sweepTo()` unbounded-loop gas-exhaustion pattern described in the reference report.

### Finding Description
Any payment message (of any asset, any amount, not just `base`) with an output to an AA address is queued as a trigger for that AA: [1](#0-0) 

When the trigger is processed, `updateInitialAABalances()` loads **all** rows the AA has ever accumulated in `aa_balances` and iterates over every one of them, regardless of whether the current trigger involves that asset: [2](#0-1) 

If the trigger includes an asset that is not yet in `aa_balances`, a new row is inserted, permanently growing the set for that address: [3](#0-2) 

Asset definition itself is a normal single-authored message with no restriction preventing arbitrary users from repeatedly defining trivial new assets: [4](#0-3) 

There is no limit anywhere on the number of *distinct* assets an address (in particular an AA address) may hold in `aa_balances`; the only caps that exist bound the number of assets *within a single unit* (`MAX_MESSAGES_PER_UNIT`, checked in `validateAATriggerObject`) or per asset definition (`MAX_DENOMINATIONS_PER_ASSET_DEFINITION`), not the cumulative count across many separate triggering units over time: [5](#0-4) 

Because a new, distinct asset can be issued and sent to the target AA in every unit, an attacker can keep inserting new rows into `aa_balances` for that AA indefinitely, at low, constant cost per row. Each subsequent trigger of the victim AA (which can be triggered by anyone, including the attacker, or simply by normal usage) then pays for a `SELECT` and `forEach` over the entire accumulated set, an O(n) cost that grows without bound as n (the number of distinct assets ever sent) increases — this is the same “unbounded array traversal driven by an attacker-controlled, ever-growing collection” bug class as `sweepTo()` iterating over `assets` in the reference report.

### Impact Explanation
As the attacker keeps growing `aa_balances` for a targeted AA, the fixed per-trigger cost of `updateInitialAABalances` (DB read + in-memory iteration) increases linearly and without bound. This directly increases:
- The wall-clock time and DB load required to process **every future trigger** of that AA, since AA trigger handling runs synchronously as part of unit stabilization under the write lock (`aa_composer.handleAATriggers`, invoked from `main_chain.js`/`writer.js`).
- The practical usability of the AA: legitimate users' payments to the AA will be processed increasingly slowly, and past some point the AA can become effectively unusable/stuck, freezing any funds/logic that depend on the AA responding in a timely manner.
- Because every full node must independently replay the same unbounded loop to reach consensus on the AA's response, this is a node-agnostic (not single-hub) computational DoS: all validating nodes pay the same increasing cost, which can slow down stabilization/processing for units touching that AA network-wide.

This matches the accepted impact categories: AA fund freezing / loss of availability, and degraded ability of the network to timely confirm units related to the affected AA.

### Likelihood Explanation
Likelihood is high: asset issuance and payments to any address (including AA addresses) are permissionless, cheap, single-message operations available to any unprivileged user (an "asset issuer"/"AA trigger sender"). No special conditions, admin permissions, or high value transfers are required — only repeated distinct asset definitions plus a minimal payment of each to the victim AA, which is exactly the reachable trigger vector described in the rules (unprivileged unit poster / AA trigger sender / asset issuer).

### Recommendation
- Cap the number of distinct assets an AA (or any address relying on `aa_balances`) can accumulate, e.g. reject/ignore triggers in assets beyond a maximum distinct-asset-per-address limit, or require the AA to explicitly "opt in" to holding new assets.
- Alternatively/additionally, avoid the full-table iteration in `updateInitialAABalances`; only fetch/touch the balance rows for the specific asset(s) referenced by the current trigger (`WHERE address=? AND asset IN (?)`) instead of `WHERE address=?` for all assets, since only assets in `trigger.outputs` are needed for the current computation — the "read all rows and update those not matching only in-memory" pattern is the direct cause of the unbounded per-trigger cost.
- Consider charging a growing fee or requiring bond/burn per new asset introduced into an AA's balance, or purging zero-balance/dust entries so the accumulation cannot be weaponized for cheap linear griefing.

### Proof of Concept
1. Attacker repeatedly posts `asset` definition messages (cheap, single-authored units) to create `N` distinct new assets A1..AN.
2. For each asset Ai, attacker posts a `payment` message sending a minimal amount of Ai to the victim AA's address; per `main_chain.js` `handleAATriggers`, this queues a trigger for the AA (no minimum-amount restriction for non-`base` assets, and the AA doesn't need to reference Ai to be triggered).
3. Each such trigger causes `updateInitialAABalances` (`aa_composer.js:475-541`) to `INSERT` a new row into `aa_balances` for the AA (since Ai was previously unseen for that AA).
4. After N iterations, `aa_balances` for the AA has N rows.
5. Any subsequent legitimate trigger to the AA now pays an O(N) query+iteration cost in `updateInitialAABalances`, which grows unbounded as the attacker repeats step 1-3, degrading throughput and eventually causing timeouts/severe slowdowns for anyone interacting with that AA.

### Citations

**File:** main_chain.js (L1691-1706)
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
```

**File:** aa_composer.js (L244-250)
```javascript
	var arrAssets = Object.keys(trigger.outputs).filter(function(asset) {return asset !== 'base'});
	if (arrAssets.length >= constants.MAX_MESSAGES_PER_UNIT)
		return handle("too many assets");
	if (!ValidationUtils.isPositiveInteger(trigger.outputs.base))
		return handle("no base payment");
	if (!arrAssets.every(function(asset){return ValidationUtils.isPositiveInteger(trigger.outputs[asset])}))
		return handle("invalid output amount")
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

**File:** validation.js (L2725-2736)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");
```
