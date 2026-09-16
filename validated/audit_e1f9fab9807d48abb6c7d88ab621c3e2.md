## Title
Stale/invalid `issue` input rows are not excluded by sequence when checking if a capped asset "already issued" - (File: `aa_composer.js`)

### Summary
When an Autonomous Agent (AA) response issues a capped asset, `aa_composer.js`'s `issueAsset()` decides whether the cap has already been consumed by running:
```js
conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
    if (rows.length > 0) // already issued
        return cb2('already issued');
    addIssueInput(1);
});
``` [1](#0-0) 

Unlike every other double-spend/uniqueness check in the codebase, this query does **not** filter out rows belonging to `final-bad` (i.e., permanently rejected/"deleted") units.

### Finding Description
Throughout `validation.js`, whenever the engine needs to know whether some resource (an input, a spend proof, an issue) is "real", it explicitly excludes `sequence='final-bad'` rows, because a `final-bad` unit is defined as a non-existent competitor whose claims must never block anything:
- `checkInputDoubleSpend` builds its query with `AND sequence!='final-bad'` [2](#0-1) 
- the transfer-input path explicitly treats a stable `final-bad` output as spendable/non-existent and even resurrects its content from an archive cache rather than treating the reference as authoritative [3](#0-2) 
- spend-proof double-spend detection also excludes `sequence!='final-bad'` [4](#0-3) 

`issueAsset()`'s "already issued" check breaks this invariant: it joins only the `inputs` table with no join to `units`/`sequence`, so a row belonging to a unit that later becomes `final-bad` (e.g., an AA response generated as part of a `bSecondary`/pre-stabilization trigger evaluation that ends up on the losing side of an MC reorg, per the `mci, objMcUnit, bSecondary` parameters of `handleTrigger`) is treated exactly like a valid, permanently-recorded issuance [5](#0-4) . The comment in the code ("only our AA can issue, no unstable consensus-breaking issues possible") is the (incorrect) justification for skipping the sequence filter that every other code path applies.

This is the direct analog of the microweber bug: a resource (the capped-asset "issue" record) that should be treated as deleted/non-existent once its owning unit is `final-bad` continues to be exposed and honored by a later check, blocking legitimate future use of that resource.

### Impact Explanation
Once a capped asset's tentative `issue` input row is created inside a response unit that later becomes `final-bad`, `issueAsset()` will forever report `'already issued'` for that asset — even though the cap was never actually issued into circulation (the `final-bad` unit's outputs are non-existent/non-spendable). Because `objAsset.cap` assets can only ever be issued once (`serial_number` must be 1 for capped assets), this permanently and irrecoverably freezes the AA's ability to ever mint the asset it defined, matching the "AA fund loss or freezing" impact class.

### Likelihood Explanation
Any ordinary AA trigger sender can reach this path: it only requires triggering an AA that defines a capped asset and, in the same or an early/secondary response, attempts to issue it via a `payment` message requesting more of that asset than the AA currently holds (the exact scenario exercised by the "recently defined asset"/"issue recently defined asset" tests) [6](#0-5) . If that particular AA response unit ends up on a losing/`final-bad` branch (a normal, non-malicious occurrence during MC reorgs while a secondary trigger's containing unit is still unstable), the stale `issue` row remains in `inputs` and blocks all subsequent legitimate issuance attempts by the same AA for that asset. No special privileges or malicious peers are required — this is a normal-usage node-disagreement/asset-freezing bug triggered purely by ordinary trigger posting under an ordinary reorg.

### Recommendation
Add the same safeguard used everywhere else in the validation/consensus code: join `inputs` to `units` and require `sequence!='final-bad'` (and ideally restrict to `is_unique=1` or stable+good rows) in the "already issued" query inside `issueAsset()`:
```js
conn.query(
  "SELECT 1 FROM inputs JOIN units USING(unit) WHERE inputs.type='issue' AND inputs.asset=? AND units.sequence!='final-bad'",
  [asset], ...
);
```
This ensures that only genuinely valid/serial issuances count against the cap, and a rejected/`final-bad` tentative response can no longer permanently freeze the asset.

### Proof of Concept
1. Define an AA whose oscript, upon trigger, both defines a capped asset (`app: 'asset', payload: { cap: ... }`) and issues/sends it via a `payment` message in the same response (as in the "issue recently defined asset" test) [6](#0-5) .
2. Send a trigger to this AA while the surrounding unit is still unstable so the response is generated as a secondary/tentative response (`bSecondary`), causing `handleTrigger` to build a response unit containing the `issue` input row via `issueAsset()` [7](#0-6) .
3. Cause (or await) a normal main-chain reorg such that this particular response unit ends up `final-bad` while a different response/trigger path becomes the accepted one.
4. Trigger the AA again to issue the same capped asset: `issueAsset()` runs `SELECT 1 FROM inputs WHERE type='issue' AND asset=?`, finds the stale row from the `final-bad` unit, and returns `'already issued'` even though the cap was never actually put into circulation, permanently blocking issuance of that asset.

### Citations

**File:** aa_composer.js (L1175-1212)
```javascript
			function issueAsset(cb2) {
				var objAsset = assetInfos[asset];
				if (objAsset.issued_by_definer_only && address !== objAsset.definer_address)
					return cb2("not a definer");
				var issue_amount = objAsset.cap || (target_amount - total_amount);

				function addIssueInput(serial_number){
					var input = {
						type: "issue",
						amount: issue_amount,
						serial_number: serial_number
					};
					payload.inputs.unshift(input);
					total_amount += issue_amount;
					var change_amount = total_amount - target_amount;
					if (change_amount > 0)
						payload.outputs.push({ address: address, amount: change_amount });
					cb2();
				}
				
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
				}
				else{
					conn.query( // filtered by our AA's address, all equally visible on all nodes
						"SELECT MAX(serial_number) AS max_serial_number FROM inputs WHERE type='issue' AND asset=? AND address=?",
						[asset, address],
						function(rows){
							var max_serial_number = (rows.length === 0) ? 0 : rows[0].max_serial_number;
							addIssueInput(max_serial_number+1);
						}
					);
				}
			}
```

**File:** validation.js (L1651-1654)
```javascript
		checkForDoublespends(conn, "spend proof", 
			"SELECT address, unit, main_chain_index, sequence FROM spend_proofs "+ doubleSpendIndexMySQL+" JOIN units USING(unit) WHERE unit != ? AND sequence!='final-bad' AND ("+arrEqs.join(" OR ")+")",
			[objUnit.unit], 
			objUnit, objValidationState, function(cb2){ cb2(); }, cb);
```

**File:** validation.js (L2266-2269)
```javascript
				else
					doubleSpendWhere += " AND asset IS NULL";
				// final-bad units are treated as non-existent competitors (their inputs.is_unique is kept NULL)
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere+" AND sequence!='final-bad'";
```

**File:** validation.js (L2456-2461)
```javascript
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
								if (src_output.sequence === 'final-bad')
									return cb("spending a stable final-bad output " + input.unit);
							}
```

**File:** test/aa_composer.test.js (L450-526)
```javascript
test.cb.serial('issue recently defined asset', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { define: true }, address: trigger_address };

	// a chain of 3 AA responses
	// 1. define asset, save var['asset'] state var, and send bytes to bouncer AA
	// 2. bouncer reflects the bytes back
	// 3. the 1st AA acts again, it reads the state var and issues the asset

	var bouncer_aa = ['autonomous agent', {
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 1000}"}
					]
				}
			},
		]
	}];
	var bouncer_address = objectHash.getChash160(bouncer_aa);
	addAA(bouncer_aa);

	var asset_aa = ['autonomous agent', {
		messages: {
			cases: [
				{
					if: "{trigger.data.define}",
					messages: [
						{
							app: 'asset',
							payload: {
								cap: 1e6,
								is_private: false,
								is_transferrable: true,
								auto_destroy: false,
								fixed_denominations: false,
								issued_by_definer_only: true,
								cosigned_by_definer: false,
								spender_attested: false,
							}
						},
						{
							app: 'payment',
							payload: {
								asset: 'base',
								outputs: [
									{address: bouncer_address, amount: "{trigger.output[[asset=base]] - 1000}"}
								]
							}
						},
						{
							app: 'state',
							state: `{
								var['asset'] = response_unit;
							}`
						}
					]
				},
				{
					if: `{trigger.address == '${bouncer_address}' AND var['asset']}`,
					messages: [{
						app: 'payment',
						payload: {
							asset: "{var['asset']}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{asset[var['asset']].cap}"}
							]
						}
					}]
				},
			]
		}
	}];
	var asset_address = objectHash.getChash160(asset_aa);
```
