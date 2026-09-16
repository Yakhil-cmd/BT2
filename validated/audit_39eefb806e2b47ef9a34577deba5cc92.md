### Title
TOCTOU-style trust of unauthenticated cached pruned-output data when validating payment inputs - (File: validation.js, archiving.js)

### Summary
`validatePaymentInputsAndOutputs()` first checks the `outputs`/`units` tables for a spent input's source output. When that row shows `address IS NULL` (content already stripped locally by the pruning/archiving process) and `sequence='final-bad'`, the code substitutes `address`, `amount`, `denomination`, and `asset` from an in-memory cache (`archiving.getCachedOutput()`) that was populated at an earlier, unrelated point in time (when the unit was pruned), instead of re-deriving/re-verifying this data against the unit's cryptographic content hash at the moment it is used to accept or reject the current transaction.

### Finding Description
The check ("is this output missing because it was locally stripped?") and the use ("substitute cached fields and proceed with input-address ownership, denomination, and double-spend checks") are two separate operations separated in time by the pruning process, exactly the check-then-use pattern behind CVE-2018-16872 (lstat metadata gathered once, then a different open()/readdir() call trusts that metadata later, while the underlying object can have changed in between).

- The cache is populated by `cachePrunedJoint()` [1](#0-0)  whenever `updateMinRetrievableMciAfterStabilizingMci()` strips a `final-bad` unit's content and replaces the DB row with a NULL-address stub [2](#0-1) .
- `getCachedOutput()` later returns whatever `{address, amount, denomination, asset}` was stored in that cache entry, keyed purely by `(unit, message_index, output_index)`, with no re-hash or re-signature check against the unit that is actually being spent [3](#0-2) .
- In `validatePaymentInputsAndOutputs()`, when the authoritative row lacks an address (stripped), the code blindly copies these cached values into `src_output` and continues the normal input-validation flow (owner check, denomination check, double-spend check) as if they came from the database [4](#0-3) .
- The cache entry is purged after `PRUNED_JOINT_CACHE_TTL_ms` (1 hour) by a `setInterval` sweep [5](#0-4) , and the same in-memory map is written to and read from without any synchronization with the concurrent DB transaction that is doing the validation, so the value seen by a validating unit poster can be from a joint that no longer matches the DB's current view of that unit's stability/sequence state.

Because the substitution path is reached only through the `sequence='final-bad'` && "already stripped locally" branch, and the surrounding `bStableInParents` branch (lines 2455-2460) that rejects spending a stable final-bad output is evaluated on a possibly different (pre-strip) `main_chain_index`/`sequence` view than the one the cache was populated under, a unit whose spent input is only "final-bad" and pruned in some but not all replaying validators' views can be treated inconsistently: nodes that still have the row unstripped correctly reject the spend (final-bad), while a node that already pruned it fills in the cached values and continues validating, without re-confirming that the *current* consensus state agrees that this output is actually spendable or unspendable.

### Impact Explanation
Divergent local caches can make a poster's unit accepted by some nodes (who reconstruct the output from the local pruned-joint cache and pass all downstream checks) and rejected by others (who still see the full, non-stripped final-bad row and hit the explicit `"spending a stable final-bad output"` rejection at line 2459-2460), producing a node disagreement on the validity of the unit — one of the accepted analog impact classes (node disagreement on validity/stability).

### Likelihood Explanation
This path is reachable by any ordinary unit poster who references, as a payment input, an output that belongs to a unit that has become `final-bad` and has since been locally pruned by the validating node (a state that occurs naturally as part of normal DAG evolution/pruning, not requiring special network position). No peer/hub/node compromise is required to trigger the divergent code path — only crafting a payment message with an `input.unit` pointing at such an output.

### Recommendation
Do not resurrect spending-eligibility decisions from the best-effort `assocCachedPrunedJoints` cache. Either (a) always re-derive stripped output data by requesting the full joint from peers and re-verifying its hash/signature before allowing it to satisfy an input (as already done in the `!objCachedOutput` branch), or (b) persist the minimal immutable fields needed for input validation (`address`, `amount`, `denomination`, `asset`, `sequence`) in the database row itself when stripping, instead of relying on a volatile, TTL-based, unauthenticated in-process cache that can disagree with the authoritative on-disk state.

### Proof of Concept
1. Node A prunes a `final-bad` unit `U` (content stripped, row `address=NULL`), populating `assocCachedPrunedJoints[U]` with `output.address = X`.
2. Attacker posts a new unit `V` whose payment input references `U`'s output as a source, with `input.address` set to `X` and owned by one of `V`'s authors.
3. On Node A (which has pruned `U`), `validatePaymentInputsAndOutputs()` hits the `!src_output.address` branch, retrieves the cached output via `archiving.getCachedOutput()`, and continues validating `V` using those cached fields.
4. On Node B (which has not pruned `U`, or pruned it under a different `main_chain_index`/`sequence` snapshot), the same lookup either fails to match the cached expectations or the `bStableInParents` branch rejects `V` outright with `"spending a stable final-bad output"`.
5. The two nodes reach different validity conclusions for `V`, demonstrating a node disagreement on validity driven by trusting stale, unauthenticated cached data instead of re-verifying it at the point of use.

### Citations

**File:** archiving.js (L10-19)
```javascript
function cachePrunedJoint(objJoint){
	assocCachedPrunedJoints[objJoint.unit.unit] = { objJoint: objJoint, expiry_ts: Date.now() + PRUNED_JOINT_CACHE_TTL_ms };
}

function getCachedPrunedJoint(unit){
	const cached = assocCachedPrunedJoints[unit];
	if (!cached)
		return null;
	return cached.objJoint;
}
```

**File:** archiving.js (L21-38)
```javascript
// looks up a specific output within a cached pruned joint, in the same shape as the outputs table columns we lost to stripping
function getCachedOutput(unit, message_index, output_index){
	const objJoint = getCachedPrunedJoint(unit);
	if (!objJoint)
		return null;
	const message = objJoint.unit.messages && objJoint.unit.messages[message_index];
	if (!message || message.app !== 'payment' || !message.payload)
		return null;
	const output = message.payload.outputs && message.payload.outputs[output_index];
	if (!output)
		return null;
	return {
		address: output.address,
		amount: output.amount,
		denomination: message.payload.denomination || 1,
		asset: message.payload.asset || null
	};
}
```

**File:** archiving.js (L40-46)
```javascript
function purgeExpiredCachedPrunedJoints(){
	const now = Date.now();
	for (let unit in assocCachedPrunedJoints)
		if (assocCachedPrunedJoints[unit].expiry_ts < now)
			delete assocCachedPrunedJoints[unit];
}
setInterval(purgeExpiredCachedPrunedJoints, PRUNED_JOINT_CACHE_TTL_ms);
```

**File:** storage.js (L1706-1746)
```javascript
		// strip content off units older than min_retrievable_mci
		conn.query(
			// 'JOIN messages' filters units that are not stripped yet
			"SELECT DISTINCT unit, content_hash FROM units "+db.forceIndex('byMcIndex')+" CROSS JOIN messages USING(unit) \n\
			WHERE main_chain_index<=? AND main_chain_index>=? AND sequence='final-bad'", 
			[min_retrievable_mci, prev_min_retrievable_mci],
			function(unit_rows){
				var arrQueries = [];
				async.eachSeries(
					unit_rows,
					function(unit_row, cb){
						var unit = unit_row.unit;
						console.log('voiding unit '+unit);
						if (!unit_row.content_hash)
							throw Error("no content hash in bad unit "+unit);
						readJoint(conn, unit, {
							ifNotFound: function(){
								throw Error("bad unit not found: "+unit);
							},
							ifFound: function(objJoint){
								var objUnit = objJoint.unit;
								var objStrippedUnit = {
									unit: unit,
									content_hash: unit_row.content_hash,
									version: objUnit.version,
									alt: objUnit.alt,
									parent_units: objUnit.parent_units,
									last_ball: objUnit.last_ball,
									last_ball_unit: objUnit.last_ball_unit,
									authors: objUnit.authors.map(function(author){ return {address: author.address}; }) // already sorted
								};
								if (objUnit.witness_list_unit)
									objStrippedUnit.witness_list_unit = objUnit.witness_list_unit;
								else if (objUnit.witnesses)
									objStrippedUnit.witnesses = objUnit.witnesses;
								if (objUnit.version !== constants.versionWithoutTimestamp)
									objStrippedUnit.timestamp = objUnit.timestamp;
								var objStrippedJoint = {unit: objStrippedUnit, ball: objJoint.ball};
								batch.put('j\n'+unit, JSON.stringify(objStrippedJoint));
								archiving.cachePrunedJoint(objJoint); // keep the full content around for a while in case somebody still needs it
								archiving.generateQueriesToArchiveJoint(conn, objJoint, 'voided', arrQueries, cb);
```

**File:** validation.js (L2462-2474)
```javascript
							if (!src_output.address) {
								if (src_output.sequence === 'final-bad' && src_output.main_chain_index < storage.getMinRetrievableMci()) { // already stripped locally
									const objCachedOutput = archiving.getCachedOutput(input.unit, input.message_index, input.output_index);
									if (!objCachedOutput) // ask the peer who sent this unit. If the peer doesn't respond but other nodes have accepted the unit, they'll share it with us, we'll get here again and request input.unit from them
										return cb({error_code: "unresolved_dependency", arrMissingUnits: [input.unit], bRequestPrunedContent: true});
									src_output.address = objCachedOutput.address;
									src_output.amount = objCachedOutput.amount;
									src_output.denomination = objCachedOutput.denomination;
									src_output.asset = objCachedOutput.asset;
								}
								else
									return cb("output being spent " + input.unit + " not found");
							}
```
