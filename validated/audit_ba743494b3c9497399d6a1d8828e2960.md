### Title
Unbounded per-asset balance growth in `aa_balances` lets an attacker poison an Autonomous Agent's storage, freezing legitimate future triggers - (File: aa_composer.js)

### Summary
Hubble's `MarginAccount.weightedAndSpotCollateral()` iterates over every collateral asset a trader has ever deposited, with no minimum-deposit check and no way to prune assets, so an attacker can dust-deposit many collaterals to make every future margin/liquidation call increasingly (and eventually prohibitively) expensive. The analogous flow in ocore is the per-address `aa_balances` bookkeeping performed on **every** trigger to an Autonomous Agent (AA) in `updateInitialAABalances()`. The set of distinct assets tracked for an AA address grows without bound and without any minimum-amount check, and the full set is re-loaded, looped over, and (for existing assets present in the new trigger) turned into one `UPDATE` query per asset, on every single subsequent trigger sent to that AA - by anyone, not just the attacker.

### Finding Description
`handleTrigger()` calls `updateInitialAABalances()` for every trigger unit addressed to an AA [1](#0-0) . Unless a dry-run `assocBalances` cache is supplied, it queries **all** rows of `aa_balances` for the AA address and iterates over the entire result set: [2](#0-1) 

For every asset the AA has ever received (even in amounts as small as 1), the loop runs `reintroduceBalanceBug`/comparisons and, when the current trigger also touches that asset, schedules an additional `UPDATE aa_balances ...` query to be executed via `async.series` [3](#0-2) . Any newly-seen assets are appended to a single, unbounded `INSERT INTO aa_balances (...) VALUES (...), (...), ...` statement whose size scales with the number of distinct assets in that trigger [4](#0-3) .

There is no lower bound on payment amounts to an AA and no mechanism to remove an asset from `aa_balances` once it is created — this mirrors the missing "minimum deposit" and missing "collateral removal" gaps called out in the Hubble report. The only existing safeguard, `validateAATriggerObject()`, caps the number of *distinct assets referenced in a single trigger unit* (`arrAssets.length >= constants.MAX_MESSAGES_PER_UNIT`) [5](#0-4) , but this does nothing to stop an attacker from spreading the poisoning across many separate low-value trigger units over time — since asset issuance and dust payments are both permissionless and cheap, an attacker can create thousands of distinct assets and send 1 unit of each in successive units to the target AA, permanently growing that AA's row set in `aa_balances`.

Because `updateInitialAABalances()` runs synchronously as part of consensus-critical AA-trigger processing (`handleTrigger`, invoked from `handleAATriggers` while advancing the main chain) [6](#0-5) , every subsequent — even entirely legitimate — trigger to the poisoned AA now pays the cost of loading and looping over the whole poisoned asset list, and possibly issuing one SQL statement per previously-poisoned asset that is also referenced in the new trigger.

### Impact Explanation
This maps to the "AA fund loss or freezing" acceptance category: an AA that a malicious actor has poisoned with a large number of dust-asset balances becomes progressively more expensive, and can be pushed past practical/DB limits (e.g. huge multi-row `INSERT` statement, large number of chained `UPDATE` queries in `async.series`) to process on every trigger. Users who send legitimate payments to that AA afterward have their triggers processed through this bloated, ever-growing balance table, degrading or effectively freezing the AA's ability to respond and return/forward funds — analogous to Hubble's liquidation calls reverting for a poisoned account. Unlike a purely transient network-DoS, the damage here is durable: because there is no way to prune `aa_balances` entries once created, the poisoning is permanent for the affected AA address, matching the "AA fund loss or freezing" criterion rather than a resource-only nuisance.

### Likelihood Explanation
Likelihood is high for any popular AA (e.g., DEX, exchange bot) whose address is publicly known: creating new assets and sending 1-unit payments is cheap and permissionless in ocore, and there is no minimum payment amount enforced for a trigger to be processed and recorded in `aa_balances`. The attack does not require any special privilege, node compromise, or network position — it only requires the attacker to be an ordinary unit poster issuing assets and posting payment units, both of which are core reachable paths for an unprivileged asset issuer/AA trigger sender.

### Recommendation
- Enforce a minimum payment amount (per asset) that qualifies for insertion into `aa_balances`, so dust deposits below a configured threshold do not create new tracked-asset rows for an AA.
- Cap the total number of distinct assets an AA address may accumulate in `aa_balances`, or otherwise bound the cost of `updateInitialAABalances()` independent of how many distinct assets have ever been sent to the AA (e.g., paginate/limit the query, or charge growing storage/processing fees proportional to the number of tracked assets, similar to `updateStorageSize()`'s existing storage-size accounting).
- Consider allowing garbage collection of zero-balance asset rows in `aa_balances` for an address once fully spent, so an attacker cannot leave a permanent, ever-growing footprint after briefly funding and then draining dust balances.

### Proof of Concept
1. Attacker issues N distinct assets (permissionless `asset` message type), each with minimal setup cost.
2. Attacker sends a separate unit to victim AA address `X` for each asset, each containing a payment output of 1 unit of a new asset (`trigger.outputs = {assetK: 1}`), staying under the single-trigger `MAX_MESSAGES_PER_UNIT` asset cap.
3. Each of these units triggers `handleTrigger()` → `updateInitialAABalances()`, which inserts a new row into `aa_balances` for `(X, assetK, 1)` [4](#0-3) .
4. After N such units, `aa_balances` for address `X` contains N distinct asset rows.
5. Any subsequent legitimate trigger to `X` now causes `updateInitialAABalances()` to load and iterate all N rows [7](#0-6) , growing the processing cost of every future trigger to `X` linearly with N, with no mechanism ever available to reduce N back down.

### Citations

**File:** aa_composer.js (L244-246)
```javascript
	var arrAssets = Object.keys(trigger.outputs).filter(function(asset) {return asset !== 'base'});
	if (arrAssets.length >= constants.MAX_MESSAGES_PER_UNIT)
		return handle("too many assets");
```

**File:** aa_composer.js (L399-400)
```javascript
// the result is onDone(objResponseUnit, bBounced)
function handleTrigger(conn, batch, trigger, params, stateVars, arrDefinition, address, mci, objMcUnit, bSecondary, arrResponses, onDone) {
```

**File:** aa_composer.js (L474-475)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
```

**File:** aa_composer.js (L492-514)
```javascript
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
