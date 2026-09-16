### Title
Unbounded `aa_balances` per-asset accumulation lets an attacker DoS an AA's trigger processing - (File: aa_composer.js)

### Summary
`handleTrigger`'s `updateInitialAABalances` function loads **every** asset balance row an AA address currently holds and iterates over the full result set on every single trigger, regardless of how small or targeted the trigger is. Because asset issuance in ocore is permissionless (any account can issue a new asset cheaply), an attacker can flood an AA's escrow/address with outputs denominated in a huge number of distinct, attacker-issued assets, inflating the `aa_balances` table for that address indefinitely. This mirrors the Canto coinswap bug where `GetAllBalances`/`GetPoolBalances` iterates an attacker-inflatable coin array, causing gas exhaustion; here the analogous unbounded loop runs during consensus-critical AA trigger handling.

### Finding Description
`updateInitialAABalances` (the non-`bAir` branch) does:
```js
conn.query(
    "SELECT asset, balance FROM aa_balances WHERE address=?",
    [address],
    function (rows) {
        var arrQueries = [];
        rows.forEach(function (row) { ... }); // iterates over ALL assets ever accumulated at this address
        ...
    }
);
``` [1](#0-0) 

This query and the subsequent `.forEach` are unconditional — they run for **every** trigger sent to the AA, not just triggers that reference many assets; `trigger.outputs` (bounded by `MAX_OUTPUTS_PER_PAYMENT_MESSAGE`/message limits) only determines which subset of rows get an `UPDATE`, but the full row set from `aa_balances` is always fetched and looped over in JavaScript (`rows.forEach`, `rows.map`) before any per-invocation complexity/op-count limits are applied by the oscript engine. [2](#0-1) 

Because asset creation (`type: 'issue'` / asset definition messages) is permissionless and cheap in ocore, an attacker can:
1. Issue an arbitrarily large number of distinct assets.
2. Send a small payment output of each distinct asset to a target AA's address across many units.
3. Each such payment (once stabilized/response-triggering) causes a new row to be inserted into `aa_balances` for that (address, asset) pair via the `arrNewAssets` insert path. [3](#0-2) 

Once `aa_balances` for the target AA address contains a very large number of rows, **every subsequent trigger** to that AA — sent by any legitimate, unprivileged user — forces every full node to run the `SELECT ... WHERE address=?` and iterate over the entire (attacker-inflated) row set as part of consensus-critical unit validation/AA response computation, before the AA's own bounce_fees/complexity-limited script logic is ever reached.

This is directly analogous to the Canto finding: `k.bk.GetAllBalances` unconditionally iterates an attacker-inflatable `Coins` array during `AddLiquidity`/`RemoveLiquidity`; here `SELECT asset, balance FROM aa_balances WHERE address=?` unconditionally iterates an attacker-inflatable per-address asset-balance set during every AA trigger.

### Impact Explanation
If an attacker inflates the number of distinct assets held by a specific AA's address sufficiently, subsequent triggers to that AA become expensive to validate for every node (query + JS-side loop over potentially thousands of rows), executed synchronously as part of the deterministic trigger-handling pipeline that all validating/witnessing nodes must run to agree on the AA's response. This can:
- Slow down or effectively freeze that AA's ability to process new triggers in a timely, resource-bounded way, denying its legitimate users/counterparties funds availability (AA fund freezing/DoS).
- Since this occurs inside consensus-relevant processing (`handleTrigger` is invoked while computing AA responses that become part of the DAG/state), a sufficiently large blow-up risks nodes disagreeing on timing/availability of processing resources or stalling AA response computation for the targeted AA, which is consensus-critical for that AA's users.

This is bounded to the specific targeted AA (not the whole chain), similar to how the Canto bug only affected a specific coinswap pool, which is consistent with the Medium severity classification given in the reference report.

### Likelihood Explanation
- Asset issuance in ocore is permissionless and inexpensive — unlike Canto's coinswap pools, which required whitelisted denominations (the very fact Canto's own maintainers used to downgrade severity), ocore places **no equivalent whitelist restriction** on which assets can be sent to an AA address.
- Sending payments to an arbitrary AA address (its target) is a normal, unprivileged action available to any unit poster.
- The only cost to the attacker is the (small) per-asset issuance/definition fee and per-output transaction fees, both of which are cheap relative to the potential ongoing DoS of the targeted AA.

### Recommendation
- Avoid unconditionally loading the full `aa_balances` row set for an address on every trigger. Instead, query only the balances of assets relevant to the current trigger (`trigger.outputs` keys) plus `base`, analogous to the Canto fix of only querying the specific coin denominations needed (`StandardDenom`, `CounterpartyDenom`, `LptDenom`) instead of `GetAllBalances`.
- If full-balance introspection is required elsewhere (e.g., `formula/evaluation.js` `balance` references), consider capping/pruning the number of distinct asset balances an address may accumulate, or charging asset-issuance/storage fees proportional to state growth caused to third-party AA addresses.
- Add a hard cap on the number of distinct assets that may be tracked per AA address in `aa_balances`, and reject/ignore payments that would push a targeted address beyond this cap in a way that avoids silently dropping user funds (e.g., bounce oversized asset novelty).

### Proof of Concept
1. Attacker issues N distinct assets (e.g., N = 10,000) via cheap `asset` definition messages — permissionless, unlike Canto's whitelisted pool denominations.
2. For each asset, attacker sends a minimal payment output of that asset to `AA_TARGET` address, in units that eventually stabilize; each stabilized payment (per `updateInitialAABalances`'s `arrNewAssets` insert path) adds one new row to `aa_balances(address=AA_TARGET, asset=X, balance>0)`. [3](#0-2) 
3. After N rows accumulate for `AA_TARGET`, any ordinary user sends a normal, small trigger to `AA_TARGET`.
4. Every full node processing this trigger executes `SELECT asset, balance FROM aa_balances WHERE address=?` returning N rows, then `rows.forEach(...)` over all N rows in `updateInitialAABalances`, before the AA's own script-level complexity/op-count limits apply. [4](#0-3) 
5. Repeating this against larger N escalates the fixed per-trigger overhead for `AA_TARGET`, degrading or effectively denying timely processing of legitimate triggers to that AA across the network.

### Citations

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
