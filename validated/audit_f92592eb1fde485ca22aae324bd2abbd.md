### Title
AA capped-asset issuance can be permanently frozen because `issueAsset()` checks "already issued" without excluding voided (`final-bad`) issue inputs - (File: aa_composer.js)

### Summary
When an Autonomous Agent (AA) sends a payment message that needs to fund itself by issuing its own capped asset, `aa_composer.js`'s `issueAsset()` decides whether the asset was "already issued" with a query that ignores unit finality/sequence, unlike the consensus-level validation logic which explicitly excludes `final-bad` units from this check. If the AA's original issuing response ever ends up `final-bad` (voided, e.g. because it lost a fork/double-spend resolution), the composer will forever believe the capped asset "already issued" and will refuse to compose a new issuing unit, even though the network-level validation would actually accept a fresh issue. This permanently freezes the AA's ability to mint its own capped supply, mirroring the reported bug class: a helper that decides "is this action allowed/available" without accounting for a state flag (here, `sequence`/finality) that actually invalidates the record it is looking at.

### Finding Description
`issueAsset()` in `aa_composer.js` decides whether a capped asset can still be issued with: [1](#0-0) 
which runs `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` with no `sequence`/`is_stable` filter at all. The same pattern exists in the wallet/composer path in `inputs.js`: [2](#0-1) 

Contrast this with the actual consensus rule enforced during unit validation, which explicitly treats `final-bad` (voided/invalidated) units as **non-existent competitors** and excludes them from the double-spend/uniqueness check for issue inputs: [3](#0-2) 

Rows for `final-bad` units are never deleted from the `inputs` table; only their `is_unique` flag is cleared, as seen in the stabilization logic that marks losing units `final-bad` and nulls `is_unique` (rather than removing the row): [4](#0-3) [5](#0-4) 

So if the AA's first attempt to issue its capped asset (an `issue` input inside its own response unit) ends up on the losing side of a fork/double-spend and becomes `final-bad`, that row still satisfies `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` in `issueAsset()`. From then on, every subsequent trigger that requires the AA to issue this asset will hit `cb2('already issued')` and bounce, even though the real network-level state (per `validation.js`) would allow the issuance to proceed, because the `final-bad` unit is not a real competitor.

This directly parallels the reported Vault bug: a helper (`_depositable`/`_withdrawable`) makes an availability decision using a stale/incomplete view of state (ignoring `paused`), causing operations that should succeed to fail. Here, `issueAsset()`'s "already issued" check makes an availability decision using a stale/incomplete view of state (ignoring `sequence`), causing operations that should succeed (re-issuing after the losing branch became final-bad) to fail forever.

### Impact Explanation
Any AA pattern that defines a capped asset and issues it lazily (e.g., only once the definer/trigger requests it, or via multiple potential trigger paths that could race — as shown in `test/aa_composer.test.js`'s "issue recently defined asset" test which relies on chained secondary triggers to perform the issue) is exposed. If the specific response unit performing the `issue` input is ever resolved as `final-bad` (e.g., loses a double-spend/fork at the unit-authoring/witnessing level), the AA can never again mint its capped-supply asset — all subsequent triggers attempting the issuance are bounced with `already issued`. Since the AA's whole mechanism (and any dependent contract/exchange logic) typically expects that capped supply to eventually exist and be distributed to users, this is a permanent, unrecoverable freezing of that asset's supply and of any AA-held/promised funds denominated in it.

### Likelihood Explanation
This requires a scenario where an AA's issuing response unit becomes non-serial and is finally resolved `final-bad`. AA response units are typically deterministic, but the underlying unit (authored by the AA and referencing units/parents on the DAG) can still become part of a losing fork depending on network conditions or if a secondary-trigger chain runs more than once due to race conditions in when different trigger paths reach the issuance branch. This is a narrower trigger condition than a straightforward one-shot exploit, so likelihood is Medium, but the resulting freeze is permanent and not self-healing once it occurs.

### Recommendation
Align `issueAsset()`'s "already issued" check with the same exclusion logic used in `validation.js`: filter out `final-bad` units (and ideally require the row be `is_stable=1 AND sequence='good'` or come from another AA response, matching the check already used elsewhere for `is_issued` in `formula/evaluation.js`): [6](#0-5) 
i.e. join `units` and require `sequence!='final-bad'` (or `sequence='good'`) before concluding the capped asset was already issued, in both `aa_composer.js` and `inputs.js`.

### Proof of Concept
1. Deploy an AA that defines a capped asset and, in a later branch (e.g., in response to a returning secondary trigger, as in the "issue recently defined asset" test pattern), issues that asset via a `payment` message with an `issue` input.
2. Arrange for that specific issuing response unit to become part of a losing fork so it is finally resolved as `sequence='final-bad'` (its `inputs` row remains with `type='issue'`, `asset=<capped_asset>`, only `is_unique` is nulled).
3. Trigger the AA again along the same code path that should perform the issuance.
4. Observe that `issueAsset()`'s query `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` still returns the stale `final-bad` row, causing `cb2('already issued')` and bouncing the trigger — permanently, on every future attempt — even though `validateAssetDefinition`/`validatePaymentInputsAndOutputs` in `validation.js` would not treat that `final-bad` row as a blocking competitor for a genuinely new issuance.

### Citations

**File:** aa_composer.js (L1195-1201)
```javascript
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
				}
```

**File:** inputs.js (L264-269)
```javascript
		if (objAsset.cap){
			conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
				if (rows.length > 0) // already issued
					return finish();
				addIssueInput(1);
			});
```

**File:** validation.js (L2268-2269)
```javascript
				// final-bad units are treated as non-existent competitors (their inputs.is_unique is kept NULL)
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere+" AND sequence!='final-bad'";
```

**File:** main_chain.js (L1343-1349)
```javascript
								else{
									arrFinalBadUnits.push(row.unit);
									// treat this unit as a non-existent competitor from now on
									conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], function(){
										setContentHash(row.unit, cb);
									});
								}
```

**File:** main_chain.js (L1391-1393)
```javascript
			conn.query("UPDATE units SET sequence='final-bad' WHERE unit IN(?)", [arrSpendingUnits], function(){
			  // treat these units as non-existent competitors from now on
			  conn.query("UPDATE inputs SET is_unique=NULL WHERE unit IN(?)", [arrSpendingUnits], function(){
```

**File:** formula/evaluation.js (L1565-1567)
```javascript
							conn.query("SELECT 1 FROM inputs CROSS JOIN units USING(unit) WHERE type='issue' AND asset=? AND (main_chain_index<=? AND is_stable=1 AND sequence='good' " + (bAA ? "OR is_aa_response=1" : "") + ") LIMIT 1", [asset, mci], function(rows){
								cb(rows.length > 0);
							});
```
