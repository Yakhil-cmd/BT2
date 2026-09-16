### Title
Permanent DOS on capped-asset issuance by AA due to stale "already issued" check that ignores unit sequence/`is_unique` state - ([File: aa_composer.js])

### Summary
The nomination-pool report describes a state-consistency bug: a control variable (`staked`) is cleared prematurely at one lifecycle stage (`start_unbond`) but the actual gating logic that decides whether a new action is allowed is checked against that stale variable, permanently blocking legitimate future actions (DOS on `stake`). The same class of bug — a control-flow check based on a database record that is written once but never revisited when the underlying transaction is later invalidated — exists in the ocore AA asset-issuance logic in `aa_composer.js`.

### Finding Description
When an Autonomous Agent issues a capped asset, `issueAsset()` in `aa_composer.js` decides whether the asset has "already been issued" purely by checking for the existence of any row in `inputs` with `type='issue'` for that asset, without regard to whether that row's owning unit ever became final-bad (non-serial): [1](#0-0) 

Contrast this with every other balance-relevant query in the same function, which correctly restricts to `sequence='good'` (and, for unstable AA-originated outputs, filters through the `aa_addresses`/is_unique machinery): [2](#0-1) 

Elsewhere in the codebase, when a unit is later determined to be non-serial ("final-bad") during main-chain stabilization, its `inputs` rows are not deleted — only `is_unique` is set to `NULL`, effectively voiding the input's uniqueness claim while the row (with `type='issue'`, `asset`, `serial_number`) still physically remains in the table: [3](#0-2) 

Because `issueAsset()`'s "already issued" check does not filter by `sequence='good'` or `is_unique=1`, once any unit containing a capped-asset `issue` input for that asset becomes final-bad (e.g., because another input consumed in the same trigger-response unit conflicts with a competing spend, making the whole unit non-serial), the row persists in `inputs` and the check will forever report `'already issued'` for that asset, even though the issue was voided and the asset's supply was never actually created. The identical wallet-side composer function in `inputs.js` has the same unfiltered query pattern: [4](#0-3) 

### Impact Explanation
If the AA's issuance response unit for a capped asset is ever rendered final-bad, the AA can never issue that asset again — the capped asset supply is permanently frozen at zero (or at whatever partial state existed before invalidation), since `issueAsset()` will always return `'already issued'` for every future trigger. Depending on the AA's logic, this can also freeze all AA funds that are conditioned on successful asset issuance (funds sent to the AA in anticipation of receiving the asset become unspendable/stuck), matching the "AA fund loss or freezing" impact category.

### Likelihood Explanation
Reaching this state requires that a unit containing the capped-asset issue input becomes non-serial. Because AA response units are single-authored by the AA and consume the AA's own previously-received outputs (guarded by per-address processing), a genuine double-spend race on those specific inputs is uncommon under normal conditions. However, non-seriality can still occur through conflicting inputs in the same response unit or through catch-up/reorg edge cases handled by `findStableConflictingUnits`, making this a real but narrower-likelihood path — consistent with a Medium severity rating, as in the source report.

### Recommendation
The "already issued" existence check in `issueAsset()` (both `aa_composer.js` and `inputs.js`) should be restricted to inputs belonging to units with `sequence='good'` (and ideally `is_unique=1`), mirroring the filtering already used for `readStableOutputs`/`readUnstableOutputsSentByAAs`. This ensures the issuance-gating state stays consistent with the unit's actual finalized validity, the same fix pattern recommended in the source report (keep the gating flag consistent with the true underlying state through the full lifecycle, not just an early-stage side effect).

### Proof of Concept
1. An AA defines and issues a capped asset in a response unit `U1`, inserting an `inputs` row with `type='issue', asset=A`.
2. `U1` also spends another input (e.g., a byte input) that ends up conflicting with a competing unit, causing `U1` to become `sequence='final-bad'` during stabilization (`main_chain.js` `handleNonserialUnits`), which sets `is_unique=NULL` for `U1`'s inputs but does not delete the row.
3. A later trigger causes the AA to attempt to issue asset `A` again via `issueAsset()`.
4. The query `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` still finds the row from `U1` (regardless of its `final-bad` sequence/`is_unique=NULL` status) and returns `'already issued'`, permanently blocking issuance of asset `A` even though it was never actually produced.

### Citations

**File:** aa_composer.js (L1145-1154)
```javascript
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
```

**File:** aa_composer.js (L1195-1200)
```javascript
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
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

**File:** inputs.js (L264-269)
```javascript
		if (objAsset.cap){
			conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
				if (rows.length > 0) // already issued
					return finish();
				addIssueInput(1);
			});
```
