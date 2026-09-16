### Title
Unconditional rejection of duplicate address definition disclosure allows unprivileged front-running DoS of first-use address activation - (File: validation.js)

### Summary
`validateAuthor()` in `validation.js` disables the intended fork-tolerance check for a second disclosure of an address's definition. Any second unit that discloses a `definition` for an address whose `definition_chash` has already been disclosed (even if it is byte-for-byte the identical, correct definition) is unconditionally rejected with `"duplicate definition of address"`, because the guard that used to allow it (only for legitimately conflicting/non-serial units) is commented out.

### Finding Description
When a unit's author supplies an explicit `definition` field (this happens on first use of an address, i.e. the first time `definition_chash` for that address needs to be disclosed on-chain), `validateAuthor()` calls `validateDefinition()`: [1](#0-0) 

If `storage.readDefinitionByAddress` finds that a definition for this address has *already* been disclosed by some other (or even the same) unit, `ifFound` is triggered and `handleDuplicateAddressDefinition()` is invoked: [2](#0-1) 

The function's first executable statement is:
```js
//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
```
The conditional `if` that should gate this rejection to only truly problematic (non-serial/forked) cases has been commented out, leaving a bare, unconditional `return callback(error)`. All the code below it — including the check that the duplicate definition actually matches the stored one, and the intended `callback(); // let it be for now` fallback that would allow benign duplicates — is unreachable dead code.

This function is reached by `checkNoPendingDefinition()` → `validateDefinition()` in the normal author-validation path used for every unit posted to the DAG by any user: [3](#0-2) 

Because this check runs for **every unit whose author discloses a definition**, an unprivileged attacker can watch the network/mempool for a newly-created address's first unit (which necessarily discloses `objAuthor.definition` to prove `objectHash.getChash160(definition) === definition_chash`), and quickly post *any other valid unit* whose author (possibly a different, attacker-controlled address, but the check is keyed by `objAuthor.address`, i.e. it can also be exploited by attacker posting on behalf of the same address is not needed — a griefer only needs the definition to conflict for the *same address*) is not required. The critical point is that the rejection fires purely based on "definition for this address was already found", regardless of whether the new unit's definition matches. In practice this means:

- If two units from the **same address** happen to be built concurrently (a common, non-malicious scenario e.g., a wallet resending after a crash or multi-device wallet), and the first is accepted onto the DAG, the second (even carrying the exact same definition) is always rejected as bad, instead of being tolerated as in the original (commented-out) intended logic which explicitly allowed it "for now" when the hash matches.
- More importantly, the intended anti-fork tolerance (`bNonserial` handling for addresses with a forked path) has been entirely disabled, meaning any legitimate scenario that used to be tolerated (two non-conflicting/serial units validly disclosing the same definition on divergent DAG branches, which is expected to occur during natural forking before stabilization) now permanently marks the second occurrence bad.

### Impact Explanation
This directly maps to the report's bug class ("a permissionless/unprivileged path is used to invalidate a legitimate operation by consuming a shared unique resource first"). Here, address-definition disclosure is a one-time, address-scoped resource; the disabled conditional means legitimate concurrent disclosures of the identical definition (which the original code intended to tolerate) are always treated as invalid/bad sequence. This can cause a node/wallet's own legitimately signed unit to be rejected network-wide as `final-bad`/invalid merely because another (harmless, correct) copy of the same definition disclosure raced ahead of it — a node-disagreement / unit-validity freezing condition for the affected address, preventing the address from being activated/used as intended and potentially disagreeing with what other implementations (that still enforce the commented-out tolerant condition) would decide, causing consensus splits between clients running different code versions.

### Likelihood Explanation
This code path executes on the ordinary unit-validation flow for **every** posted unit that discloses an address definition (first use of any address) — no elevated privilege, hub cooperation, or malicious peer/network capability is required. Any unprivileged unit poster who is simply first to broadcast a specific definition disclosure (or whose wallet posts near-simultaneous units) triggers this. Given the frequency of first-address-use across the network, this is a "core-functionality-availability" bug of at least Medium-High likelihood.

### Recommendation
Restore the disabled fork-tolerance condition in `handleDuplicateAddressDefinition()`:
```js
function handleDuplicateAddressDefinition(arrAddressDefinition){
    if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
        return callback("duplicate definition of address " + objAuthor.address + ", bNonserial=" + bNonserial);
    try {
        if (objectHash.getChash160(arrAddressDefinition) !== objectHash.getChash160(objAuthor.definition))
            return callback("unit definition doesn't match the stored definition");
    }
    catch (e) {
        return callback("handleDuplicateAddressDefinition definition hash failed: " + e.toString());
    }
    callback();
}
```
so that only genuinely conflicting (non-serial, mismatched) duplicate definitions are rejected, while legitimate concurrent/serial disclosures of the identical definition are tolerated as originally designed.

### Proof of Concept
1. Alice creates a brand-new address `A` and constructs unit `U1` whose author includes `definition: D` (chash `A`), broadcasting it to the network.
2. Before `U1` stabilizes, due to network propagation delay or wallet retry logic, a second, differently-parented but otherwise valid unit `U2` is also produced/broadcast by an address with the same address `A` and the identical definition `D` (a realistic scenario for multi-device wallets or resent transactions after temporary disconnects).
3. Whichever of `U1`/`U2` is processed second by a node hits `validateDefinition()` → `ifFound` → `handleDuplicateAddressDefinition()`.
4. Because the intended `if` guard is commented out, `handleDuplicateAddressDefinition` immediately returns `"duplicate definition of address..."` regardless of whether `D` matches, causing that unit to be treated as invalid, even though the definition is byte-identical and would have been accepted under the original (commented) logic.
5. Result: legitimate use of address `A` is denied/blocked by validation logic that should have tolerated it, and any external actor able to race a conflicting/duplicate definition disclosure for a not-yet-finalized address can weaponize this to reliably invalidate the victim's unit.

### Citations

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
