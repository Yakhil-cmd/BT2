## Title
Deterministic child-AA addresses can be pre-funded with unexpected assets before definition, polluting the AA's balance state at activation - (File: `storage.js`, `aa_composer.js`)

### Summary
Obyte AA addresses are deterministic content hashes of their JSON definition (`chash160`), so a future AA's address can be computed and known before that AA is ever defined/activated on the DAG — directly analogous to a CREATE2-precomputed contract address. Any unprivileged unit poster can pre-fund such a predictable address with an arbitrary asset before the AA that will live there is actually defined. When the AA is finally defined, `storage.insertAADefinitions` unconditionally folds *all* pre-existing unspent outputs sent to that address into the AA's `aa_balances`, regardless of the asset type or whether the sender had any relationship to the AA's intended trigger flow.

### Finding Description
AA definitions are frequently generated dynamically inside another AA's formula and their address is computed in advance via `chash160()`, exactly like a CREATE2 salt/address precomputation. This pattern is demonstrated in the "factory AA" test, where `$child_aa_address = chash160($child_aa)` is computed before the `definition` message that actually creates the child AA is even posted: [1](#0-0) 

Because this address is fully deterministic and can be derived off-chain by anyone who can reproduce the child AA template (e.g., by simulating the factory's `init` formula, or simply observing the factory's oscript source, which is public), an attacker can send a payment with any asset to that address *before* the factory AA ever executes and defines it.

When the child AA is eventually defined, `storage.insertAADefinitions` computes its initial balances by summing **all** unspent, `sequence='good'` outputs ever sent to that address, with no restriction on which asset or which sender: [2](#0-1) 

The accompanying comment confirms this is by design for legitimate non-AA payments received between definition and stabilization, but the same code path equally absorbs payments from a malicious actor sent to the not-yet-existing address: [3](#0-2) 

Subsequent triggers on this AA read balances purely as flat per-asset numeric sums via `aa_balances`/`assocBalances`, with no concept of "expected asset" or object identity checks: [4](#0-3) 

Unlike the ERC-1155 case where an array-length invariant hard-reverts the contract, ocore's balance model is purely additive/fungible, so the received foreign asset does not break unit validation. However, any child-AA logic that branches on `balance[this_address][asset]` (rather than strictly on `trigger.output[[asset=...]]`) to determine "first funding", exact expected amounts, or asset-specific accounting will silently observe an attacker-controlled, pre-polluted balance the moment it activates.

### Impact Explanation
An attacker who can predict a to-be-defined AA's address (a common pattern for factory/child AAs and parameterized AAs) can pre-load that address with foreign assets or extra base bytes before the AA is defined. If the child AA's formula makes decisions based on its own total balance (e.g., "if this is the first payment", or computing shares/ratios from `balance[this_address][...]`) rather than solely on the current trigger's declared outputs, the attacker's pre-funding silently corrupts that decision, potentially causing the AA to misallocate or lock funds for legitimate users (AA fund loss or freezing) once activated — the same class of impact ("loss of availability"/broken invariant from pre-deployment funding") judged Medium in the original report.

### Likelihood Explanation
Exploitation requires: (1) an AA design pattern that computes a child/parameterized AA address deterministically and later relies on `balance[address][asset]` rather than purely on `trigger.output`, and (2) the attacker being able to reproduce that address computation ahead of time (straightforward, since oscript source and the address-generating formula are public or replayable). Both conditions are realistic for factory-pattern AAs, which are an officially supported and documented use case (see the "define new AA and activate it" and "AA with generated definition of new AA" tests).

### Recommendation
- When designing or documenting factory/child-AA patterns, explicitly warn AA authors that a child AA's initial `balance[this_address][asset]` may include funds sent before the AA was formally defined, and that state-initialization logic must not rely on balance to detect "first activation."
- Consider providing a way for `insertAADefinitions` to expose (or for the getters/state layer to expose) the split between "balance received via the defining trigger's own payment" vs. "balance accumulated from arbitrary pre-existing outputs," so that AA authors relying on balance-based initialization checks can distinguish legitimate funding from attacker pre-funding.

### Proof of Concept
1. Observe (or replicate) a factory AA's `init` formula that computes `$child_aa_address = chash160($child_aa)` for a deterministic child AA template (as in `test/aa_composer.test.js:922-1011`).
2. Before the factory AA is triggered (i.e., before the child AA's `definition` message is posted on-chain), send a payment of an unrelated asset directly to `$child_aa_address`.
3. Trigger the factory AA normally; it posts the `definition` message and its expected payment to the child AA.
4. `storage.insertAADefinitions` (storage.js:954-961) sums *all* unspent outputs ever sent to the child address — including the attacker's pre-funded payment — into `aa_balances`.
5. Any subsequent trigger of the child AA that inspects `balance[this_address][asset]` (via the formula `balance[...]` operator, `aa_composer.js:491-527`) observes the attacker's injected balance merged in, potentially skewing conditional logic that assumes balance reflects only legitimate trigger payments.

### Citations

**File:** test/aa_composer.test.js (L944-963)
```javascript
	var factory_aa = ['autonomous agent', {
		init: `{
			$child_aa = ['autonomous agent', {
				bounce_fees: { base: 10000 },
				doc_url: 'https://myapp.com/description.json',
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							init: "{response['received_amount'] = trigger.output[[asset=base]];}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
							]
						}
					}
				]
			}];
			$child_aa_address = chash160($child_aa);
		}`,
```

**File:** storage.js (L936-939)
```javascript
						}
						// we need to recalc the balances to reflect the payments received from non-AAs between definition and stabilization
						bAlreadyPostedByUnconfirmedAA = true;
						console.log("will recalc balances after repeated definition of AA " + address + " in unit " + unit);
```

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

**File:** aa_composer.js (L491-527)
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
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
```
