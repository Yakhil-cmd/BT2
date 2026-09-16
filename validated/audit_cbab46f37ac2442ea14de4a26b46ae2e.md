### Title
Capped-asset "already issued" check in AA issue-input composition can be permanently poisoned by a non-final losing double-spend, freezing an AA's asset issuance forever - (File: aa_composer.js)

### Summary
When an autonomous agent (AA) needs to issue a capped asset as part of a `payment` message, `completePaymentPayload()`'s `issueAsset()` helper decides whether the cap has already been used by running `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` with no filter on `sequence` or finality. This mirrors the reported `YieldStakingBase`/`YieldSetERC721TokenData` pattern: a "resource already locked/used" guard that does not distinguish between a legitimately committed usage and a transient/losing usage, so the resource becomes permanently unusable by its rightful owner unless a costly workaround is performed.

### Finding Description
In `aa_composer.js`, `completePaymentPayload()` builds an AA-generated payment. When the AA doesn't have enough of `asset` in its outputs and the asset is capped, it calls `issueAsset()`: [1](#0-0) 

```
if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
    conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
        if (rows.length > 0) // already issued
            return cb2('already issued');
        addIssueInput(1);
    });
}
```

This query checks for *any* row of `type='issue'` for the asset in the `inputs` table, regardless of `sequence` (`good`, `temp-bad`, or `final-bad`) and regardless of `is_unique` (which is set to `NULL` for losing branches of a double-spend by the validator, but the row itself is not deleted at that point): [2](#0-1) 

The `inputs` unique constraint that is supposed to enforce "no double issue" is `(asset, denomination, serial_number, address, is_unique)`, and issue inputs for capped assets always use `serial_number=1`: [3](#0-2) [4](#0-3) 

If the capped asset is not `issued_by_definer_only`, the double-spend/uniqueness check for `type='issue'` inputs does not even constrain by `address` (`if (objAsset && !objAsset.issued_by_definer_only) doubleSpendWhere += " AND address=?"`), meaning any address can post a competing `issue` input for the same capped asset/denomination/serial_number=1 and create a fork: [5](#0-4) 

Once such a competing unit is posted and later loses the fork (becomes non-`good` sequence, e.g. `final-bad`), its `inputs` row is not necessarily removed from the `inputs` table on all code paths before/at the time `issueAsset()`'s unconditional `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` runs. Because that query filters neither by `sequence='good'` nor excludes `final-bad`/non-unique rows, the AA permanently believes the cap has already been issued ("already issued") even though the genuine, stable issuance by the AA itself never occurred. This is structurally identical to the reported bug: a resource-state check (`lockerAddr == address(0)` / here, "no existing issue row") that is too coarse, blocking the legitimate owner (the AA, which is supposed to be the sole issuer of its own capped asset) from ever completing the intended action, with no compensating mitigation (no "same owner may proceed" carve-out as recommended in the report's Option 2).

### Impact Explanation
If an AA is designed to issue a capped asset lazily (only mint it the first time it is actually needed to fund a payment), and a race/fork occurs where a losing branch also attempted (or appears in the `inputs` table as having attempted) an `issue` input for that same asset, the AA's `issueAsset()` path will report `'already issued'` for the lifetime of the node's database, permanently blocking the AA from ever minting its capped supply. Consequences:
- AA fund/logic freezing: the AA can never issue the asset it needs to pay users, and any AA logic depending on that asset (rewards, bonds, governance tokens, etc.) is permanently broken.
- Requires manual intervention/AA redefinition to work around, analogous to the reported bug's requirement to fully "unwind" (pay back the loan first) to bypass the incorrect once-only restriction.
- Because the check is not restricted to `sequence='good'`, no attacker action is even strictly required — a natural, non-malicious fork/rollback scenario involving a stray `issue` input for the asset can trigger the permanent block; a motivated attacker could deliberately create such a competing `issue` input (since, for non-`issued_by_definer_only` capped assets, any address may submit one) to guarantee the freeze.

### Likelihood Explanation
Likelihood depends on whether stale/losing `type='issue'` rows genuinely persist in the `inputs` table after their unit becomes non-`good`. This code path was reached and confirmed to lack sequence filtering; however, full confirmation that a `final-bad` unit's `inputs` rows are never purged before the `issueAsset` check runs would require deeper tracing through `main_chain.js`'s stabilization/pruning logic than could be completed in the available search budget — this is flagged as **unconfirmed** and would benefit from direct code review of `main_chain.js`'s final-bad handling and any pruning of `inputs` for such units. Given the structural resemblance to the audited bug class (an unconditional existence check standing in for a "successfully committed" check) and the fact that the query demonstrably omits `sequence`/`is_unique` filtering, the likelihood of a real freeze is credible but should be validated with a concrete repro before treating this as fully proven.

### Recommendation
Restrict the "already issued" check to committed, winning issuances only, mirroring Option 2 from the referenced report (distinguish the rightful/legitimate actor's state from stale/losing state) rather than treating any historical row as a permanent block:
```
SELECT 1 FROM inputs JOIN units USING(unit)
WHERE inputs.type='issue' AND inputs.asset=? AND units.sequence='good' AND inputs.is_unique=1
```
Additionally, ensure `final-bad` units' `inputs` rows are pruned (or otherwise excluded) so that a losing double-spend can never permanently poison future issuance checks for the same asset.

### Proof of Concept
1. Define a capped asset (`cap` set) whose issuance is not `issued_by_definer_only`, definable/issuable in principle by an AA `A` (`objAsset.definer_address` can equal `A`, but the uniqueness check for `type='issue'` inputs of this asset does not constrain by `address` per [6](#0-5) ).
2. Before the AA `A` ever triggers its own issuance, have any address `B` post a unit with a `payment` message containing an `issue` input for that same asset with `serial_number=1` (allowed since `objAsset.cap` implies `serial_number` must be `1` per [7](#0-6) , and no `address` constraint applies to the double-spend/uniqueness check for this asset).
3. Have a second address `C` post a conflicting fork also issuing the same asset/serial_number=1 (creating a double-spend on the `type='issue'` input); the validator marks the losing branch's `is_unique=NULL` but does not necessarily delete the `inputs` row per [2](#0-1) .
4. Trigger AA `A` so it needs to issue the capped asset via `issueAsset()`. The unconditional query `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` at [1](#0-0)  finds the stray row from step 2/3 (regardless of its sequence/is_unique state) and returns `'already issued'`, permanently preventing AA `A` from ever completing its own legitimate capped-asset issuance.

### Citations

**File:** aa_composer.js (L1195-1200)
```javascript
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
```

**File:** validation.js (L2274-2296)
```javascript
					function acceptDoublespends(cb3){
						console.log("--- accepting doublespend on unit "+objUnit.unit);
						var sql = "UPDATE inputs SET is_unique=NULL WHERE "+doubleSpendWhere+
							" AND (SELECT is_stable FROM units WHERE units.unit=inputs.unit)=0";
						if (!(objAsset && objAsset.is_private)){
							objValidationState.arrAdditionalQueries.push({sql: sql, params: doubleSpendVars});
							objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
							return cb3();
						}
						mutex.lock(["private_write"], function(unlock){
							console.log("--- will ununique the conflicts of unit "+objUnit.unit);
							conn.query(
								sql, 
								doubleSpendVars, 
								function(){
									console.log("--- ununique done unit "+objUnit.unit);
									objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
									unlock();
									cb3();
								}
							);
						});
					}, 
```

**File:** validation.js (L2321-2327)
```javascript
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
					if (bIssue)
						return cb("only one issue per message allowed");
					bIssue = true;
```

**File:** validation.js (L2360-2373)
```javascript
					doubleSpendWhere = "type='issue'";
					doubleSpendVars = [];
				//	if (objAsset && objAsset.fixed_denominations){
						doubleSpendWhere += " AND denomination=?";
						doubleSpendVars.push(denomination);
				//	}
					if (objAsset){
						doubleSpendWhere += " AND serial_number=?";
						doubleSpendVars.push(input.serial_number);
					}
					if (objAsset && !objAsset.issued_by_definer_only){
						doubleSpendWhere += " AND address=?";
						doubleSpendVars.push(address);
					}
```

**File:** initial-db/byteball-mysql.sql (L294-297)
```sql
	PRIMARY KEY (unit, message_index, input_index),
	UNIQUE KEY bySrcOutput(src_unit, src_message_index, src_output_index, is_unique), -- UNIQUE guarantees there'll be no double spend for type=transfer
	UNIQUE KEY byIndexAddress(type, from_main_chain_index, address, is_unique), -- UNIQUE guarantees there'll be no double spend for type=hc/witnessing
	UNIQUE KEY byAssetDenominationSerialAddress(asset, denomination, serial_number, address, is_unique), -- UNIQUE guarantees there'll be no double issue
```
