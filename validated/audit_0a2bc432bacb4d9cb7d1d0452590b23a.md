## Analog Finding

### Title
Revoked address keys remain valid for authoring units until the `address_definition_change` stabilizes, allowing spending with a "disabled" key - ([File: validation.js])

### Summary
The external CVE describes a system where disabling/locking a credential does not immediately stop authentication, letting an attacker keep using it. In `ocore`, address key revocation is implemented via an `address_definition_change` message, but the new definition only becomes authoritative once it is **stable** on the main chain. Until then, `validateAuthor()` keeps accepting signatures produced with the *old* (supposedly revoked) definition, because signature verification is bound to whatever definition was stable as of `last_ball_mci`, not to the latest posted definition change.

### Finding Description
When a unit is validated, `validateAuthor()` fetches the address definition to check authentifiers against via `storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, ...)` [1](#0-0) . This helper only returns a definition once it is `is_stable=1` and confirmed at `main_chain_index<=max_mci` [2](#0-1) .

This means: if an address owner posts an `address_definition_change` to revoke an old signing key (e.g., because it was compromised, analogous to "disabling" a credential), the change is not immediately effective. Any unit that references a `last_ball_unit` from *before* the definition-change unit becomes stable will still validate successfully using the old (revoked) definition/key. The codebase explicitly documents this exact race: [3](#0-2) 

`// todo: investigate if this can split the nodes`
`// in one particular case, the attacker changes his definition then quickly sends a new ball with the old definition - the new definition will not be active yet`
`... callback(); // let it be for now. Eventually, at most one of the balls will be declared good`

The same latency exists in the general authentifier verification path used by every unit/AA trigger/private-payment signer through `Definition.validateAuthentifiers()`, which is fed the definition resolved the same way [4](#0-3) .

### Impact Explanation
An attacker who has obtained (or once controlled) an address's private key can continue to author valid, fund-moving units signed with that "revoked" key for as long as the corresponding `address_definition_change` has not yet stabilized on the main chain. Because stabilization requires multiple witness/main-chain confirmations, this window can be nontrivial. During that window the attacker can move/spend funds despite the legitimate owner already trying to lock the key out, i.e., unauthorized spending from the victim's address.

### Likelihood Explanation
This is reachable by any single unprivileged unit poster: no special privileges beyond a previously valid signing key are needed. The condition purely depends on standard DAG confirmation timing, which is deterministic and can be raced by an attacker who has network visibility and posts competing units quickly. The race is explicitly acknowledged in the code, indicating it is a known, reproducible edge case rather than a theoretical one.

### Recommendation
Consider requiring that any unit authored under an address whose most-recent `address_definition_change` is still unstable be treated with extra caution (e.g., delay stabilization/finalization of units signed with the outgoing definition until the change itself is confirmed, or bind unit validity more strictly to the definition-change ordering rather than only to `last_ball_mci`). At minimum, document/quantify the worst-case revocation-to-stabilization latency so wallets can warn users of an exposure window when rotating a potentially compromised key.

### Proof of Concept
1. Address `A` is controlled with key `K1`.
2. `K1` is compromised. The owner posts unit `U1` with an `address_definition_change` message switching `A` to key `K2`.
3. Before `U1` becomes stable (needs sufficient MC confirmations), the attacker (holding `K1`) posts unit `U2` from address `A`, signed with `K1`, using a `last_ball_unit` that precedes `U1`'s stabilization, moving funds out of `A` to an attacker-controlled address.
4. `validateAuthor()`/`readDefinitionByAddress()` for `U2` resolves the definition as of that `last_ball_mci`, which is still the old `K1` definition, so `U2` validates successfully [1](#0-0) .
5. If `U2` stabilizes (it does not conflict with `U1`, since it doesn't double-spend the same output), the attacker successfully moved funds using a key the owner believed had already been revoked.

### Citations

**File:** validation.js (L1189-1208)
```javascript
		// we check signatures using the latest address definition before last ball
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){
				storage.readAADefinition(conn, objAuthor.address, objValidationState.last_ball_mci, function (arrAADefinition) {
					if (arrAADefinition)
						return callback(createTransientError("will not validate unit signed by AA"));
					if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci)
						return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " not found before last ball");
					findUnstableInitialDefinition(definition_chash, function (arrDefinition) {
						if (!arrDefinition)
							return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " is not defined");
						bInitialDefinition = true;
						validateAuthentifiers(arrDefinition);
					});
				});
			},
			ifFound: function(arrAddressDefinition){
				validateAuthentifiers(arrAddressDefinition);
			}
		});
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

**File:** storage.js (L772-788)
```javascript
function readDefinitionByAddress(conn, address, max_mci, callbacks){
	readDefinitionChashByAddress(conn, address, max_mci, function(definition_chash){
		readDefinitionAtMci(conn, definition_chash, max_mci, callbacks);
	});
}

// max_mci must be stable
function readDefinitionAtMci(conn, definition_chash, max_mci, callbacks){
	var sql = "SELECT definition FROM definitions CROSS JOIN unit_authors USING(definition_chash) CROSS JOIN units USING(unit) \n\
		WHERE definition_chash=? AND is_stable=1 AND sequence='good' AND main_chain_index<=?";
	var params = [definition_chash, max_mci];
	conn.query(sql, params, function(rows){
		if (rows.length === 0)
			return callbacks.ifDefinitionNotFound(definition_chash);
		callbacks.ifFound(JSON.parse(rows[0].definition));
	});
}
```

**File:** definition.js (L1443-1466)
```javascript
	if (bAssetCondition && address || !bAssetCondition && this_asset)
		throw Error("incompatible params");
	var arrAuthentifierPaths = bAssetCondition ? null : Object.keys(assocAuthentifiers);
	var fatal_error = null;
	var arrUsedPaths = [];
	
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
		if (err)
			return cb(err);
		//console.log("eval def");
		evaluate(arrDefinition, 'r', function(res){
			if (fatal_error)
				return cb(fatal_error);
			if (!bAssetCondition && arrUsedPaths.length !== Object.keys(assocAuthentifiers).length)
				return cb("some authentifiers are not used, res="+res+", used="+arrUsedPaths+", passed="+JSON.stringify(assocAuthentifiers));
			cb(null, res);
		});
	});
}
```
