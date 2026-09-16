## Analog Found: Single-Step `address_definition_change` With No Validation That the New Definition Is Reachable

### Title
No Two-Step Confirmation for `address_definition_change` — Address Control Can Be Irreversibly Transferred to an Unreachable Definition - ([File: validation.js])

### Summary
The Sherlock finding warns that a single-step `transferOwnership()` call lets an owner accidentally hand control to an address nobody controls, permanently breaking all `onlyOwner` functionality. ocore has a structurally identical single-step control-transfer primitive: the `address_definition_change` message, which immediately reassigns which key/definition controls an address, with validation limited to a format check rather than a check that the new controlling definition is real or ever disclosable.

### Finding Description
Any unit author can post an `address_definition_change` message that rewrites the `definition_chash` that will control their own (or, if multi-authored, a co-author's) address going forward. The inline-payload validator only checks structure and address-format validity of the new value, never that it corresponds to a definition that can ever be revealed or is otherwise sane: [1](#0-0) 

Once this message stabilizes, `readDefinitionChashByAddress`/`readDefinitionByAddress` treat the new `definition_chash` as authoritative for all future authorizations of that address — there is no "confirm"/"accept" step performed by holder of the new definition, unlike a two-step ownership-transfer pattern: [2](#0-1) 

The change is durably recorded and applied at write time without any reachability check on the target: [3](#0-2) 

The only guard preventing spam abuse is a subsequent gate on *sending anything else from that address* until the pending change stabilizes and is disclosed — but this comes after the fact, not before the reassignment is committed: [4](#0-3) 

This mirrors the reported bug class exactly: a one-step "transfer" of control (`definition_chash` = new "owner") is accepted with only a superficial format check (`isValidAddress`), with no verification that the new value is a controllable/valid target and no opt-in acceptance step by the new controller.

### Impact Explanation
If the `definition_chash` supplied in `address_definition_change` is not the hash of any definition that can ever be produced (e.g., a typo, a hash of a definition the composer doesn't actually hold the keys for, or a malformed/garbage 32-byte value that happens to pass the `isValidAddress` format check), the address becomes permanently unable to author any further units. Because subsequent authorization requires supplying a definition whose chash matches the stored `definition_chash` (see `validateDefinition`/`readDefinitionByAddress` in definition.js and validation.js), all funds and any AA/shared-address governance tied to that address are permanently frozen — the same "breaking all functions with the onlyOwner modifier" impact described in the source report, translated to ocore's address-authorization model. This qualifies as AA/asset fund freezing per the accepted impact classes.

### Likelihood Explanation
Likelihood is elevated because `address_definition_change` is a normal, frequently-used feature (key rotation, multisig re-configuration) reachable by any ordinary unit author with no special privilege, and the only check performed is a length/base32 format check, not a semantic reachability check. Composer-side tooling normally derives the value correctly, but nothing in the protocol prevents a malformed or wrong `definition_chash` from being accepted and committed irreversibly, and no "reveal/confirm" step is required before the reassignment takes effect.

### Recommendation
Introduce a two-step (commit + reveal/accept) pattern for `address_definition_change`, or at minimum require the new definition (or proof of its derivability) to accompany/precede the change before it becomes authoritative, so that a wrong or unreachable `definition_chash` cannot silently and irreversibly brick the address. At minimum, add tooling-level warnings/hard failures when composing a definition change whose resulting chash cannot be reproduced from a definition already known to the composing wallet.

### Proof of Concept
1. Compose a unit with a message `{app: "address_definition_change", payload: {definition_chash: X}}` where `X` is any syntactically valid 32-byte base32 string that is *not* the chash of any definition the sender actually controls (validated only by `isValidAddress`, see validation.js:1743-1744).
2. Sign and post the unit; it passes `validateInlinePayload` and is written via `writer.js` into `address_definition_changes`.
3. Once stable, `storage.readDefinitionChashByAddress` returns `X` as the address's authoritative `definition_chash` (storage.js:754-768).
4. Any future unit from that address must supply a definition hashing to `X`; since no such definition exists/is known, the address can never again satisfy `validateDefinition`, permanently freezing its funds — analogous to `transferOwnership` to an uncontrolled account.

### Citations

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

**File:** validation.js (L1719-1745)
```javascript
		case "address_definition_change":
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["definition_chash", "address"]))
				return callback("unknown fields in address_definition_change");
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			var address;
			if (objUnit.authors.length > 1){
				if (!isValidAddress(payload.address))
					return callback("when multi-authored, must indicate address");
				if (arrAuthorAddresses.indexOf(payload.address) === -1)
					return callback("foreign address");
				address = payload.address;
			}
			else{
				if ('address' in payload)
					return callback("when single-authored, must not indicate address");
				address = arrAuthorAddresses[0];
			}
			if (!objValidationState.arrDefinitionChangeFlags)
				objValidationState.arrDefinitionChangeFlags = {};
			if (objValidationState.arrDefinitionChangeFlags[address])
				return callback("can be only one definition change per address");
			objValidationState.arrDefinitionChangeFlags[address] = true;
			if (!isValidAddress(payload.definition_chash))
				return callback("bad new definition_chash");
			return callback();
```

**File:** storage.js (L754-768)
```javascript
function readDefinitionChashByAddress(conn, address, max_mci, handle){
	if (!handle)
		return new Promise(resolve => readDefinitionChashByAddress(conn, address, max_mci, resolve));
	if (max_mci == null || max_mci == undefined)
		max_mci = MAX_INT32;
	// try to find last definition change, otherwise definition_chash=address
	conn.query(
		"SELECT definition_chash FROM address_definition_changes CROSS JOIN units USING(unit) \n\
		WHERE address=? AND is_stable=1 AND sequence='good' AND main_chain_index<=? ORDER BY main_chain_index DESC, level DESC LIMIT 1", 
		[address, max_mci], 
		function(rows){
			var definition_chash = (rows.length > 0) ? rows[0].definition_chash : address;
			handle(definition_chash);
	});
}
```

**File:** writer.js (L184-192)
```javascript
				if (message.payload_location === "inline"){
					switch (message.app){
						case "address_definition_change":
							var definition_chash = message.payload.definition_chash;
							var address = message.payload.address || objUnit.authors[0].address;
							conn.addQuery(arrQueries, 
								"INSERT INTO address_definition_changes (unit, message_index, address, definition_chash) VALUES(?,?,?,?)", 
								[objUnit.unit, i, address, definition_chash]);
							break;
```
