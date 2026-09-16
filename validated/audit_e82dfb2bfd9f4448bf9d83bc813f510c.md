### Title
Double issuance of a capped asset within a single AA response unit due to check-before-persist ordering in `issueAsset` - (File: aa_composer.js)

### Summary
`issueAsset` (inside `completePaymentPayload`, called from `sendUnit`) determines whether a capped asset has already been issued by querying the `inputs` table with `SELECT 1 FROM inputs WHERE type='issue' AND asset=?`, *before* the AA's response unit is validated and written via `validateAndSaveUnit`/`writer.saveJoint`. If a single AA definition composes more than one `payment` message that references the same capped asset in one response unit, each message's `completePaymentPayload`/`issueAsset` call runs this "already issued" check against the not-yet-committed state, so both calls see "not issued" and both create an `issue` input with `serial_number=1` for the same capped asset in the same unit. [1](#0-0) 

### Finding Description
This mirrors the reported reentrancy class: a state check ("is this bribe/asset already registered?") is performed and passed *before* the corresponding persistent write happens, and a second call can pass the same check because the write from the first call has not landed yet. In `BribeVault`, the vulnerable window is a Solidity external call; in ocore's AA engine, the vulnerable window is the asynchronous, DB-transaction-based `issueAsset` check that runs prior to `validateAndSaveUnit`, which is the point where the unit (and its `issue` input) is actually persisted to the `inputs` table via `writer.saveJoint`. [2](#0-1) 

Compounding this, the double-spend protection in unit validation explicitly excludes the current unit from its own conflict check:
```
doubleSpendWhere += " AND unit != " + conn.escape(objUnit.unit);
```
so two `issue` inputs with the same `serial_number=1` for the same capped asset, both located in the same unit (in different payment messages), are not caught by `checkInputDoubleSpend`. [3](#0-2) 

The only defenses I could locate for issue inputs are: (a) "for capped asset serial_number must be 1" (which both issuances would satisfy, since both use serial_number 1), and (b) "only one issue per message" (`bIssue` flag), which is scoped per *payment message*, not per *unit*. I was not able to find, within the code explored, a unit-level aggregate constraint that forbids two different messages in the same unit from each issuing input for the same capped asset. [4](#0-3) 

I could not fully verify within the available tool budget whether some other later-stage check (e.g. total supply cross-check across messages, or a constraint elsewhere in validation.js/writer.js) blocks this specific same-unit double-issue scenario for capped assets. This is a real limitation of my analysis — the exact reachability and whether any missing safeguard elsewhere prevents this scenario needs to be confirmed by deeper reading of `validation.js` (full asset validation path) and `writer.js` (unit persistence, `inputs` table insert logic) in a live session.

### Impact Explanation
If reachable, this would allow an AA (or an AA author who can define an autonomous agent, which any user can do by simply posting an AA-defining unit) to construct an AA whose single response unit issues the full `cap` of a capped asset twice, inflating supply beyond the declared cap. That breaks accounting invariants relied on by users and other AAs (e.g., DEXes, token holders) that assume `cap` is an enforced upper bound on total issued amount — a supply-inflation bug matching the "Medium" severity class of the original finding (unauthorized additional minting due to a stale-check race).

### Likelihood Explanation
The AA definition author fully controls how many `payment` messages reference a given asset in a single response, and any user can create and trigger such an AA (AA creation and triggering is unprivileged in Obyte). No malicious peer/node/hub cooperation is required — it's purely a single AA's own definition and a single triggering unit, matching the "reachable from unpriviledged unit/AA author/trigger sender" requirement. However, I could not fully confirm the absence of a compensating unit-level check, so likelihood is stated with moderate confidence pending that verification.

### Recommendation
Move the "already issued" check for capped assets to occur against the currently-being-built unit's own messages as well as the DB (i.e., track issued capped assets in an in-memory set scoped to the whole `sendUnit` call, not just per payload/message), or perform the persisted DB check strictly after all messages of the unit have been finalized/reserved, and reject the unit if more than one `issue` input for the same capped asset appears across all its messages before calling `writer.saveJoint`. Additionally, add an explicit unit-level validation check (in `validation.js`, `validatePaymentInputsAndOutputs` or a preceding aggregate step) that disallows two `issue` inputs for the same capped asset within a single unit, regardless of message grouping.

### Proof of Concept
1. Define an AA whose response template contains two `payment` messages, each referencing the same capped, non-fixed-denomination asset `A` (`cap` set, `issued_by_definer_only: true`, AA is the definer), with each message's outputs requiring more funds than the AA currently holds in asset `A`, forcing `issueAsset` to run for each message.
2. Trigger the AA. During `sendUnit`, `completePaymentPayload` is invoked once per payment message; for each, `issueAsset` queries `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` against the DB — at this point in the flow (`validateAndSaveUnit` for this same response unit has not yet run), the query returns no rows for both calls.
3. Both messages therefore call `addIssueInput(1)`, producing two `issue` inputs with `serial_number=1` for asset `A` in the same response unit.
4. When `validateAndSaveUnit` runs and validation.js checks doublespends, the same-unit exclusion (`unit != objUnit.unit`) prevents the two issues in the same unit from conflicting with each other, and per-message uniqueness checks (`bIssue`) don't span messages — so (pending confirmation of no other blocking check) the unit is accepted with double the declared `cap` issued for asset `A`. [1](#0-0) [5](#0-4)

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

**File:** aa_composer.js (L1403-1411)
```javascript
						objUnit.unit = objectHash.getUnitHash(objUnit);
						console.log('unit', util.inspect(objUnit, { depth: 6 }))
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```

**File:** validation.js (L2258-2269)
```javascript
			function checkInputDoubleSpend(cb2){
			//	if (objAsset)
			//		profiler2.start();
				doubleSpendWhere += " AND unit != " + conn.escape(objUnit.unit);
				if (objAsset){
					doubleSpendWhere += " AND asset=?";
					doubleSpendVars.push(payload.asset);
				}
				else
					doubleSpendWhere += " AND asset IS NULL";
				// final-bad units are treated as non-existent competitors (their inputs.is_unique is kept NULL)
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere+" AND sequence!='final-bad'";
```

**File:** validation.js (L2308-2327)
```javascript
				case "issue":
				//	if (objAsset)
				//		profiler2.start();
					if (input_index !== 0)
						return cb("issue must come first");
					if (hasFieldsExcept(input, ["type", "address", "amount", "serial_number"]))
						return cb("unknown fields in issue input");
					if (!isPositiveInteger(input.amount))
						return cb("amount must be positive");
					if (input.amount > constants.MAX_CAP)
						return cb("issue amount too large: " + input.amount)
					if (!isPositiveInteger(input.serial_number))
						return cb("serial_number must be positive");
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
					if (bIssue)
						return cb("only one issue per message allowed");
					bIssue = true;
```
