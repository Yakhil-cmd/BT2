### Title
Reachable "unreachable code" assertion in double-spend conflict resolution can crash validating full nodes on a crafted double-spend - ([File: validation.js])

### Summary
CVE-2018-4209 describes an "unexpected interaction" between components that triggers an `ASSERT` failure — i.e., code relies on an invariant it assumes always holds, and a crafted input violates that invariant, hitting a path the developers believed unreachable. `ocore` has a structurally identical pattern in `checkForDoublespends()`: it assumes that once a conflicting record is *stable* (included in the unit's parent graph, `main_chain_index <= last_ball_mci`), its `sequence` must already have been resolved to either `good` or `final-bad`. If neither holds, the code executes `throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit)` [1](#0-0) , an unhandled synchronous throw from inside an async DB callback that will crash the Node.js process handling unit validation.

### Finding Description
`checkForDoublespends()` is invoked while validating payment inputs, outputs and spend proofs for *any* posted unit (an unprivileged unit poster can trigger this path simply by broadcasting a payment/asset transfer that double-spends an already-used output/spend-proof) [2](#0-1) .

For each conflicting record returned by the SQL query (which explicitly excludes `sequence='final-bad'`), the code branches on whether the conflicting unit is included in the new unit's parent graph:
- If included and the conflicting record's `main_chain_index` is above `last_ball_mci` or `null` ("too young"), it's rejected as a normal error.
- If included, stable, and `sequence === 'good'`, it's rejected as a normal error.
- If included, stable, and `sequence` is *neither* `good` **nor** filtered out as `final-bad` by the query (i.e. `temp-bad`), the code hits: `throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit)` [3](#0-2) .

This is the exact same class of bug as the CVE: an assumption baked into the code as an "impossible" branch, which is reachable via specific data-driven interaction. The invariant relied upon is that `temp-bad` sequence is resolved to `good`/`final-bad` exactly when a unit becomes stable, inside `markMcIndexStable()`'s `handleNonserialUnits()` — which explicitly walks stable `temp-bad` units and re-classifies them via `findStableConflictingUnits()` before allowing the stabilization pass to complete [4](#0-3) . The exact same "should never happen" assumption is also directly asserted a few hundred lines later for the *primary* input-lookup path: `if (bStableInParents) { if (src_output.sequence === 'temp-bad') throw Error("spending a stable temp-bad output " + input.unit); ... }` [5](#0-4) .

Both of these "impossible" throws are reachable if a peer/author manages to get their own conflicting spend validated (and thus written with `sequence` set) in a narrow window where the conflicting unit has already been marked `is_stable=1` in the `units` table but its `sequence` column has not yet been updated from `temp-bad` to `good`/`final-bad` by the still-in-progress stabilization transaction (`markMcIndexStable` first runs `UPDATE units SET is_stable=1 ...` and only afterward resolves `temp-bad` rows) [6](#0-5) . Any unit whose validation reads that intermediate DB state (e.g., a concurrently validated unit from a different connection, or a light node/hub race, or a crash-recovery scenario where the process restarts between the two updates) will hit the "unreachable" throw and crash the process instead of returning a controlled validation error.

### Impact Explanation
An uncaught `throw Error` inside `checkForDoublespends`'s async DB callback is not caught by the surrounding `try/catch` used elsewhere in `validate()`; it propagates as an unhandled exception and crashes the Node.js process for any full node that validates a unit hitting this branch. Because the trigger condition is data/timing-dependent rather than universally reproducible, it can affect nodes non-deterministically: some nodes crash while validating the same unit, others (that read after stabilization committed fully) do not, producing potential **disagreement on unit validity between nodes**, and repeated crashes across the network degrade the network's ability to confirm new units — the accepted impact categories for this analysis (node disagreement on validity/stability, and a network unable to confirm units).

### Likelihood Explanation
Exploitation requires crafting a double-spend scenario where the referenced conflicting unit is caught mid-stabilization (marked stable but not yet sequence-resolved) at the moment another unit referencing it is validated. This is timing-dependent and not trivially reproducible on demand, and could not be fully confirmed reachable without deeper analysis of transaction/connection isolation guarantees around `markMcIndexStable` and whether other validating connections can observe the intermediate `is_stable=1`/`sequence='temp-bad'` state (this could not be verified with certainty from the available context/tools). Given the DB updates use standard SQL `UPDATE` statements inside `db.executeInTransaction`/write locks, whether read isolation entirely prevents this window is uncertain and would need to be validated in a running environment.

### Recommendation
- Replace the `throw Error("unreachable code...")` assertions in `checkForDoublespends` (and the analogous "spending a stable temp-bad output" throw in `validatePaymentInputsAndOutputs`) with a graceful validation error (transient or unit error) instead of an unhandled crash, since the invariant is not provably guaranteed against races.
- Audit whether validation connections can read intermediate stabilization states (between `is_stable=1` and sequence resolution) and, if so, hold appropriate read locks or defer validation until stabilization fully commits.
- Add regression tests that simulate a race between `markMcIndexStable` and concurrent double-spend validation to confirm the invariant truly holds under load.

### Proof of Concept
A concrete, deterministic PoC could not be constructed with the available static analysis; reaching the "unreachable" throw depends on winning a race between unit stabilization (`markMcIndexStable`) and concurrent double-spend validation (`checkForDoublespends`) reading the `units` table in the narrow window where `is_stable=1` but `sequence` is still `temp-bad`. This would require dynamic testing/fuzzing against a running node cluster to confirm reachability and is flagged as unverified.

### Citations

**File:** validation.js (L1643-1657)
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
	
	async.series([validateSpendProofs, validatePayload], callback);
```

**File:** validation.js (L1676-1688)
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
```

**File:** validation.js (L2455-2461)
```javascript
							var bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci);
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
								if (src_output.sequence === 'final-bad')
									return cb("spending a stable final-bad output " + input.unit);
							}
```

**File:** main_chain.js (L1308-1352)
```javascript
	conn.query(
		"UPDATE units SET is_stable=1 WHERE is_stable=0 AND main_chain_index=?", 
		[mci], 
		function(){
			// next op
			handleNonserialUnits();
		}
	);


	function handleNonserialUnits(){
	//	console.log('handleNonserialUnits')
		conn.query(
			"SELECT * FROM units WHERE main_chain_index=? AND sequence!='good' ORDER BY unit", [mci], 
			function(rows){
				var arrFinalBadUnits = [];
				async.eachSeries(
					rows,
					function(row, cb){
						if (row.sequence === 'final-bad'){
							arrFinalBadUnits.push(row.unit);
							return row.content_hash ? cb() : setContentHash(row.unit, cb);
						}
						// temp-bad
						if (row.content_hash)
							throw Error("temp-bad and with content_hash?");
						findStableConflictingUnits(row, function(arrConflictingUnits){
							var sequence = (arrConflictingUnits.length > 0) ? 'final-bad' : 'good';
							console.log("unit "+row.unit+" has competitors "+arrConflictingUnits+", it becomes "+sequence);
							conn.query("UPDATE units SET sequence=? WHERE unit=?", [sequence, row.unit], function(){
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
								else{
									arrFinalBadUnits.push(row.unit);
									// treat this unit as a non-existent competitor from now on
									conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], function(){
										setContentHash(row.unit, cb);
									});
								}
							});
						});
					},
```
