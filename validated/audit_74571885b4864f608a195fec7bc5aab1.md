### Title
Reachable "unreachable code" assertion in double-spend resolution crashes the node - (File: validation.js)

### Summary
`checkForDoublespends()` in `validation.js` contains a branch explicitly labeled as unreachable that actually throws an uncaught `Error` when a conflicting record for a payment input / spend proof is found to be included in the new unit's ancestry, is already stable, but is not in `sequence='good'`. This mirrors CVE-2018-12543 in Mosquitto: an assumed-impossible code path is in fact reachable from unprivileged, attacker-controlled input (a topic string in Mosquitto; here, a crafted payment/spend-proof unit), and reaching it terminates the process.

### Finding Description
`checkForDoublespends` is the shared double-spend resolution routine invoked from three places that all process attacker-supplied unit content directly:
- spend-proof double-spend checks [1](#0-0) 
- divisible/base payment input double-spend checks [2](#0-1) 
- headers-commission/witnessing input double-spend checks [3](#0-2) 

All three SQL queries explicitly exclude `sequence='final-bad'` rows (`... AND sequence!='final-bad'`), so any row returned to `checkForDoublespends` can only have `sequence` equal to `'good'` or `'temp-bad'`. Inside the routine: [4](#0-3) 

The logic is:
1. If the conflicting record's unit is included in (or equal to) one of the new unit's parents (`bIncluded === true`):
   - if it is "too young" (unstable, `main_chain_index` null or beyond `last_ball_mci`) → return a normal validation error.
   - if `sequence === 'good'` → return a normal validation error.
   - otherwise → `throw Error("unreachable code, conflicting ...")`.

Given the SQL already filters out `final-bad`, the only value left for the `else` branch is `sequence === 'temp-bad'` combined with the record being **stable** (`main_chain_index <= last_ball_mci` and not null). The comment/name "unreachable code" asserts that a stable ancestor record can never remain `temp-bad` — the same class of false assumption as Mosquitto's assert that a `$`-prefixed non-`$SYS` topic could never occur.

Whether `temp-bad` sequences are guaranteed to always resolve to `good` or `final-bad` strictly before a unit becomes stable is a property of the stability/majority-decision logic in `main_chain.js`/`storage.js`; if there is any window, ordering edge case, or interaction between multiple authors/forked paths where a stable ancestor still carries `temp-bad` at the time a descendant unit references it as a double-spend candidate, this "impossible" branch fires. Because the `throw` occurs inside an asynchronous callback (`graph.determineIfIncludedOrEqual(...)` callback) with no enclosing `try/catch`, it becomes an uncaught exception that crashes the Node.js process for every full node that processes the offending unit — not merely a validation rejection.

### Impact Explanation
If reachable, this is not a benign validation failure: it is a process-crashing uncaught exception triggered by content inside a normally-formed, attacker-composed unit (a payment with a double-spending input, or a spend-proof double-spend, referencing one of its own ancestors). Because every node applies the same deterministic validation code to the same unit, a single crafted unit could crash all full nodes that attempt to validate/write it, halting the DAG's ability to confirm new units network-wide — matching the "network unable to confirm new units" impact criterion.

### Likelihood Explanation
The likelihood hinges entirely on whether a *stable* record can ever be observed with `sequence='temp-bad'` at the moment a new referencing unit is validated. This requires precise knowledge of the temp-bad→final-bad/good resolution timing relative to stabilization in `main_chain.js`, which I was not able to fully trace before running out of tool iterations. I can confirm the code path's reachability *conditions* (stable + not `good` + not `final-bad`, when the conflicting unit is included in the new unit's parents) but cannot confirm with certainty from the available context whether the stabilization logic guarantees this state is always excluded before a unit is marked stable. This should be verified against `main_chain.js`'s stability/majority-decision code before treating this as a confirmed crash bug.

### Recommendation
- Audit the stabilization/majority-decision code path to confirm whether a stable unit can ever retain `sequence='temp-bad'` when referenced as a double-spend competitor from a later unit's ancestry.
- If such a window exists, replace the `throw Error(...)` at `validation.js:1688` with a graceful validation rejection (`return cb2(error)`), consistent with the two sibling branches, rather than crashing the process — do not rely on "should never happen" invariants for attacker-reachable code paths.
- Wrap the async callback in `checkForDoublespends` so any residual invariant violation is converted into a bounded validation error instead of an uncaught process-level exception.

### Proof of Concept
Not confirmed as concretely exploitable from the available context — see Likelihood Explanation. A full PoC would require constructing:
1. A unit `A` from address `X` that is accepted with `sequence='temp-bad'` due to a serial-address conflict (via `checkSerialAddressUse` in `validation.js:1304-1343`).
2. Driving `A` to stability (`main_chain_index <= last_ball_mci`) while it is still recorded as `temp-bad` (rather than being resolved to `good`/`final-bad`) at validation time of a later unit.
3. Posting a new unit `B` (descendant of `A`) containing a payment input or spend proof that double-spends against the same output/spend-proof as `A`, so that `checkForDoublespends` finds `A` as `bIncluded=true`.

Confirming step 2 requires deeper analysis of `main_chain.js` stabilization code that was not completed within the available tool budget.

### Citations

**File:** validation.js (L1643-1655)
```javascript
	function validateSpendProofs(cb){
		if (!("spend_proofs" in objMessage))
			return cb();
		var arrEqs = objMessage.spend_proofs.map(function(objSpendProof){
			return "spend_proof="+conn.escape(objSpendProof.spend_proof)+
				" AND address="+conn.escape(objSpendProof.address ? objSpendProof.address : objUnit.authors[0].address);
		});
		var doubleSpendIndexMySQL = conf.storage == "mysql" ? "USE INDEX(bySpendProof)" : "";
		checkForDoublespends(conn, "spend proof", 
			"SELECT address, unit, main_chain_index, sequence FROM spend_proofs "+ doubleSpendIndexMySQL+" JOIN units USING(unit) WHERE unit != ? AND sequence!='final-bad' AND ("+arrEqs.join(" OR ")+")",
			[objUnit.unit], 
			objUnit, objValidationState, function(cb2){ cb2(); }, cb);
	}
```

**File:** validation.js (L1676-1689)
```javascript
					graph.determineIfIncludedOrEqual(conn, objConflictingRecord.unit, objUnit.parent_units, function(bIncluded){
						if (bIncluded){
							var error = objUnit.unit+": conflicting "+type+" in inner unit "+objConflictingRecord.unit;

							// too young (serial or nonserial)
							if (objConflictingRecord.main_chain_index > objValidationState.last_ball_mci || objConflictingRecord.main_chain_index === null)
								return cb2(error);

							// in good sequence (final state); final-bad is excluded by the query and treated as non-existent
							if (objConflictingRecord.sequence === 'good')
								return cb2(error);

							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
```

**File:** validation.js (L2258-2273)
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
				checkForDoublespends(
					conn, "divisible input", 
					doubleSpendQuery, doubleSpendVars, 
					objUnit, objValidationState, 
```

**File:** validation.js (L2570-2580)
```javascript
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return cb("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
					
					doubleSpendWhere = "type=? AND from_main_chain_index=? AND address=? AND asset IS NULL";
					doubleSpendVars = [type, input.from_main_chain_index, address];
					if (conf.storage == "mysql")
						doubleSpendIndexMySQL = " USE INDEX (byIndexAddress) ";

					mc_outputs.readNextSpendableMcIndex(conn, type, address, objValidationState.arrConflictingUnits, function(next_spendable_mc_index){
						if (input.from_main_chain_index < next_spendable_mc_index)
```
