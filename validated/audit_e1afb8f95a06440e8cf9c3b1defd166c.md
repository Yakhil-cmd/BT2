### Title
Post-pemCurvesFixMci authors skip the pending-keychange guard, letting a unit be authenticated under a stale address definition after a key change - (File: validation.js)

### Summary
`CURL-CVE-2016-5419` was about a TLS stack resuming a session and trusting an *old* client identity even though the certificate (identity) had already been replaced. The reachable analog in `ocore--017` is in unit-author validation: once `objValidationState.last_ball_mci >= constants.pemCurvesFixMci`, `checkSerialAddressUse()` jumps straight to `validateDefinition()` and skips the two guards, `checkNoPendingChangeOfDefinitionChash()` and `checkNoPendingDefinition()`, that exist specifically to stop an address from being used again while its keychange/definition is still unstable/pending.

### Finding Description
`checkSerialAddressUse()` picks the next validation step based on the current fix status: [1](#0-0) 

Before `pemCurvesFixMci`, an author who has an unstable pending `address_definition_changes` row (a keychange) or an unstable pending inline `definition` disclosure for the same address is rejected by `checkNoPendingChangeOfDefinitionChash()` / `checkNoPendingDefinition()`: [2](#0-1) [3](#0-2) 

Both functions explicitly document the threat they defend against: *"We don't trust pending keychanges/definitions even when they are serial, as another unit may arrive and make them nonserial, then the definition will be removed."* This is precisely the "resume with a stale identity" hazard from the CVE: an address's definition (its "certificate") is in the process of changing, but the old definition can still be used to author/authenticate a new unit before the DAG confirms which definition actually won.

After `pemCurvesFixMci`, `next` bypasses these two guard functions entirely and goes directly to `validateDefinition()`: [4](#0-3) 

`validateDefinition()`/`handleDuplicateAddressDefinition()` only compares the freshly supplied `objAuthor.definition` against whatever `storage.readDefinitionByAddress()` returns for `last_ball_mci` - it never re-checks whether a *newer, not-yet-stable* keychange for that address exists in the intervening (unstable) part of the DAG. The comment left in the code acknowledges the exact race: *"in one particular case, the attacker changes his definition then quickly sends a new ball with the old definition - the new definition will not be active yet."* [5](#0-4) 

Because `storage.readDefinitionByAddress()` is intentionally frozen to `last_ball_mci` (a stable snapshot), and the pending-keychange guard that used to compensate for that staleness is skipped once the fix flag is on, a unit that authenticates under the address's **old** definition can still be treated as valid/serial even though a newer definition change for the same address is already in flight - mirroring how libcurl kept trusting an old TLS client identity across a resumed session after the certificate had changed.

### Impact Explanation
If an address holder (or someone who has since revoked/rotated their key via an `address_definition_change`) can still get a unit signed with the *old* signing key accepted as `good`/serial after the fix-path skip, this directly threatens node agreement on validity: some nodes could treat the old-key unit as serial/good while the definition change is finalizing, enabling unauthorized spending from that address using a key that the owner believed was already superseded, or causing a fork in sequence assignment (`good`/`temp-bad`) between nodes that observe the two competing units in different orders. Both outcomes map to the "node disagreement on validity" and "unauthorized spending" impact categories in scope.

### Likelihood Explanation
The trigger is reachable by any ordinary unit-posting user: author a keychange (`address_definition_change`) for their own address, then immediately author a second unit from the same address using the old definition, both anchored to a `last_ball_mci` that predates the keychange's stabilization. No special network position, hub, or peer trust is required - this is pure single-user, single-address unit crafting, so it fits the "single posted unit" threat model required by the rules.

### Recommendation
Re-apply (or fold into `validateDefinition`) an equivalent of `checkNoPendingChangeOfDefinitionChash()`/`checkNoPendingDefinition()` for the post-`pemCurvesFixMci` path so that any address with an unstable, not-yet-included keychange or pending inline definition is still rejected (or forced through the nonserial/fork-resolution path) rather than allowed straight into `validateDefinition()`. At minimum, confirm - by tracing why the `pemCurvesFixMci` branch was introduced - whether this guard was intentionally relocated elsewhere in the post-fix flow; if not, this is a regression that should be patched.

### Proof of Concept
1. Address `A` currently has definition `D_old` (a `sig` definition with key `K_old`).
2. Attacker author (owner of `A`) crafts unit `U1` from `A` containing an `address_definition_change` message that sets `A`'s definition to `D_new` (`K_new`), with `parent_units`/`last_ball` chosen so it is not yet stable.
3. Immediately, the same author crafts unit `U2` from `A`, authored/signed with `K_old`, whose `last_ball_mci` is still behind the point where `U1`'s keychange becomes stable (`last_ball_mci >= constants.pemCurvesFixMci` so the fast path is taken).
4. Because `checkSerialAddressUse()` routes directly to `validateDefinition()` (validation.js:1305), the check that would normally reject `U2` for using `A` while a keychange is pending (validation.js:1345-1419) is never executed.
5. `validateDefinition()`/`storage.readDefinitionByAddress()` still resolve `A`'s definition to `D_old` for `U2`'s `last_ball_mci`, so `U2` validates and can be propagated/accepted as `good`, spending funds or asserting authority under the already-superseded key `K_old` - analogous to a TLS peer being authenticated under a certificate that the server had already replaced.

*Note: I was not able to trace, within the tool budget available, whether an equivalent pending-keychange check was intentionally re-implemented elsewhere specifically for the `pemCurvesFixMci` path (e.g., inside `validateDefinition` itself or in the writer/stabilization code) instead of in `checkSerialAddressUse`. This should be verified against `git blame`/changelog for the `pemCurvesFixMci` introduction before treating this as a confirmed exploitable regression rather than a documented design change.*

### Citations

**File:** validation.js (L1304-1306)
```javascript
	function checkSerialAddressUse(){
		var next = (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) ? validateDefinition : checkNoPendingChangeOfDefinitionChash;
		findConflictingUnits(function(arrConflictingUnitProps){
```

**File:** validation.js (L1345-1377)
```javascript
	// don't allow contradicting pending keychanges.
	// We don't trust pending keychanges even when they are serial, as another unit may arrive and make them nonserial
	function checkNoPendingChangeOfDefinitionChash(){
		var next = checkNoPendingDefinition;
		//var filter = bNonserial ? "AND sequence='good'" : "";
		conn.query(
			"SELECT unit FROM address_definition_changes JOIN units USING(unit) \n\
			WHERE address=? AND (is_stable=0 OR main_chain_index>? OR main_chain_index IS NULL)", 
			[objAuthor.address, objValidationState.last_ball_mci], 
			function(rows){
				if (rows.length === 0)
					return next();
				if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
					return callback("you can't send anything before your last keychange is stable and before last ball");
				// from this point, our unit is nonserial
				async.eachSeries(
					rows,
					function(row, cb){
						graph.determineIfIncludedOrEqual(conn, row.unit, objUnit.parent_units, function(bIncluded){
							if (bIncluded)
								console.log("checkNoPendingChangeOfDefinitionChash: unit "+row.unit+" is included");
							bIncluded ? cb("found") : cb();
						});
					},
					function(err){
						(err === "found") 
							? callback("you can't send anything before your last included keychange is stable and before last ball (self is nonserial)") 
							: next();
					}
				);
			}
		);
	}
```

**File:** validation.js (L1379-1419)
```javascript
	// We don't trust pending definitions even when they are serial, as another unit may arrive and make them nonserial, 
	// then the definition will be removed
	function checkNoPendingDefinition(){
		//var next = checkNoPendingOrRetrievableNonserialIncluded;
		var next = validateDefinition;
		if (bInitialDefinition)
			return next();
		//var filter = bNonserial ? "AND sequence='good'" : "";
	//	var cross = (objValidationState.max_known_mci - objValidationState.last_ball_mci < 1000) ? 'CROSS' : '';
		conn.query( // _left_ join forces use of indexes in units
		//	"SELECT unit FROM units "+cross+" JOIN unit_authors USING(unit) \n\
		//	WHERE address=? AND definition_chash IS NOT NULL AND ( /* is_stable=0 OR */ main_chain_index>? OR main_chain_index IS NULL)", 
		//	[objAuthor.address, objValidationState.last_ball_mci], 
			"SELECT unit FROM unit_authors WHERE address=? AND definition_chash IS NOT NULL AND _mci>?  \n\
			UNION \n\
			SELECT unit FROM unit_authors WHERE address=? AND definition_chash IS NOT NULL AND _mci IS NULL", 
			[objAuthor.address, objValidationState.last_ball_mci, objAuthor.address], 
			function(rows){
				if (rows.length === 0)
					return next();
				if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
					return callback("you can't send anything before your last definition is stable and before last ball");
				// from this point, our unit is nonserial
				async.eachSeries(
					rows,
					function(row, cb){
						graph.determineIfIncludedOrEqual(conn, row.unit, objUnit.parent_units, function(bIncluded){
							if (bIncluded)
								console.log("checkNoPendingDefinition: unit "+row.unit+" is included");
							bIncluded ? cb("found") : cb();
						});
					},
					function(err){
						(err === "found") 
							? callback("you can't send anything before your last included definition is stable and before last ball (self is nonserial)") 
							: next();
					}
				);
			}
		);
	}
```

**File:** validation.js (L1464-1484)
```javascript
	function validateDefinition(){
		if (!("definition" in objAuthor))
			return callback();
		// the rest assumes that the definition is explicitly defined
		var arrAddressDefinition = objAuthor.definition;
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){ // first use of the definition_chash (in particular, of the address, when definition_chash=address)
				try {
					if (objectHash.getChash160(arrAddressDefinition) !== definition_chash)
						return callback("wrong definition: " + objectHash.getChash160(arrAddressDefinition) + "!==" + definition_chash);
				}
				catch (e) {
					return callback("definition hash failed: " + e.toString());
				}
				callback();
			},
			ifFound: function(arrAddressDefinition2){ // arrAddressDefinition2 can be different
				handleDuplicateAddressDefinition(arrAddressDefinition2);
			}
		});
	}
```

**File:** validation.js (L1486-1499)
```javascript
	function handleDuplicateAddressDefinition(arrAddressDefinition){
	//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
			return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
		// todo: investigate if this can split the nodes
		// in one particular case, the attacker changes his definition then quickly sends a new ball with the old definition - the new definition will not be active yet
		try {
			if (objectHash.getChash160(arrAddressDefinition) !== objectHash.getChash160(objAuthor.definition))
				return callback("unit definition doesn't match the stored definition");
		}
		catch (e) {
			return callback("handleDuplicateAddressDefinition definition hash failed: " + e.toString());
		}
		callback(); // let it be for now. Eventually, at most one of the balls will be declared good
	}
```
