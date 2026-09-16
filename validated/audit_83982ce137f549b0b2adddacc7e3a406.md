### Title
Single-step `address_definition_change` allows irrecoverable loss/compromise of address control (no Ownable2Step-style confirmation) - ([File: validation.js], [File: writer.js], [File: storage.js])

### Summary
`ocore` lets an address holder change the signing rules for their own address by posting a single `address_definition_change` message that commits only to a `definition_chash` (a hash of the future definition). The change is validated and becomes permanent/stable after a single step, with no requirement that the new definition be disclosed, verifiable, or "accepted" before the switch takes effect — the same class of risk the report describes for `Ownable.transferOwnership` (single irreversible step) versus `Ownable2Step` (two-step, confirmed transfer).

### Finding Description
`address_definition_change` messages are validated in `validateInlinePayload` in [1](#0-0)  — the only check performed on the new definition is `isValidAddress(payload.definition_chash)`, i.e. that it is a syntactically valid 32-byte chash. There is no check that the poster actually possesses a definition whose hash matches, nor any second confirmation step.

Once the unit stabilizes, `writer.js` commits the change directly into `address_definition_changes`, replacing the address's authoritative `definition_chash` in a single step: [2](#0-1) .

From that point on, any future spend from the address must supply a `definition` whose chash matches the new `definition_chash`, checked in `validateAuthor`/`validateDefinition` in [3](#0-2) . If the `definition_chash` committed to in the original change was mistyped, corrupted, or otherwise does not correspond to a definition the user (or their cosigners) can actually produce, the address becomes permanently unspendable — there is no rollback, no acceptance step by a "new owner," and no way to re-derive a lost preimage.

The same single-step, hash-committed mechanic underlies the `'seen definition change'` / `'has definition change'` conditions used inside address definitions themselves (e.g. dead-man-switch or delegated-control patterns), evaluated in `definition.js`: [4](#0-3)  and enforced at spend time in [5](#0-4) . These constructs let an address's control be handed over to a *different* address's definition change in one step, with no requirement that the target definition be known or verifiable in advance, and no way for the network or the address owner to detect an error before the change is committed and becomes final.

This mirrors the reported bug class precisely: a critical "ownership" property (control over an address / its spending authority) can be transferred or altered in a single irreversible step, without any second-party/self confirmation that the new controlling definition is correct, known, and reachable.

### Impact Explanation
If a user (or a shared/multisig address's authorized signer) posts an `address_definition_change` with an incorrect or unreachable `definition_chash` — for example a typo, a hash computed from a definition that was never actually finalized/agreed among cosigners, or a hash derived from keys that are subsequently lost — the address's funds become permanently frozen once the change unit stabilizes, since no future unit can satisfy `objectHash.getChash160(arrAddressDefinition) !== definition_chash` unless the exact intended (and hash-matching) definition can still be produced. This is a direct funds-freezing / loss-of-control impact, analogous to the Medium-severity Ownable-vs-Ownable2Step finding: an unrecoverable, single-step change of control with no verification/acceptance step.

### Likelihood Explanation
Any address holder who has ever exercised the standard key-rotation / multisig-reconfiguration feature can trigger this by mistake (wrong chash) or by prematurely committing to a change whose members have not all finalized/exchanged the actual definition (in the shared-address flow in `wallet_defined_by_addresses.js`, cosigners exchange the definition off-chain before someone posts the on-chain `address_definition_change`; any desync between what was agreed and what is posted results in the same freeze). No attacker action is required — this is a standard, unprivileged, user-reachable path (posting a normal unit with an `address_definition_change` message), making the likelihood non-trivial for ordinary usage errors, and it also does not require malicious peers/nodes.

### Recommendation
Introduce a two-step confirmation analogous to `Ownable2Step`:
1. Require the full new definition to be disclosed and verified (chash match) in the same or a companion message before the change can be treated as authoritative, rather than only committing to a bare `definition_chash`.
2. Optionally require an explicit "accept" step signed under the new definition before the old definition's authority is revoked, so an address is never left in a state where control depends on an unverified/undisclosed definition.
3. At minimum, add wallet/UI-level safeguards that prevent submitting `address_definition_change` unless the client has already verified it can produce a valid signature under the target `definition_chash`.

### Proof of Concept
1. A wallet composes and broadcasts a unit containing an `address_definition_change` message with `definition_chash = H` for address `A`, where `H` is computed incorrectly (e.g., off-by-one byte, or computed from a definition the wallet does not actually retain), as validated by [1](#0-0) .
2. The unit passes validation (only checks that `H` is a syntactically valid chash) and is written by [6](#0-5) , then stabilizes.
3. Address `A`'s authoritative definition is now `H`. Any subsequent unit spending from `A` must supply a `definition` array whose `getChash160(...) === H`, per [7](#0-6) .
4. Since no such definition exists/is reproducible, address `A` can never again produce a valid author for any unit — all funds at `A` are permanently frozen, with no second-step or recovery path.

### Citations

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

**File:** definition.js (L352-368)
```javascript
			case 'seen definition change':
			case 'has definition change':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isArrayOfLength(args, 2))
					return cb(op+" must have 2 args");
				var changed_address = args[0];
				var new_definition_chash = args[1];
				if (bAssetCondition && (changed_address === 'this address' || new_definition_chash === 'this address' || changed_address === 'other address' || new_definition_chash === 'other address'))
					return cb("asset condition cannot reference this/other address in "+op);
				if (!isValidAddress(changed_address) && changed_address !== 'this address') // it is ok if the address was never used yet
					return cb("invalid changed address");
				if (!isValidAddress(new_definition_chash) && new_definition_chash !== 'this address' && new_definition_chash !== 'any')
					return cb("invalid new definition chash");
				if (new_definition_chash === 'any' && objValidationState.last_ball_mci < constants.anyDefinitionChangeUpgradeMci)
					return cb("too early use of 'any' in new_definition_chash");
				return cb();
```

**File:** definition.js (L835-853)
```javascript
			case 'seen definition change':
				// ['seen definition change', ['BASE32', 'BASE32']]
				var changed_address = args[0];
				var new_definition_chash = args[1];
				if (changed_address === 'this address')
					changed_address = address;
				if (new_definition_chash === 'this address')
					new_definition_chash = address;
				var and_definition_chash = (new_definition_chash === 'any') ? '' : 'AND definition_chash='+db.escape(new_definition_chash);
				conn.query(
					"SELECT 1 FROM address_definition_changes CROSS JOIN units USING(unit) \n\
					WHERE address=? "+and_definition_chash+" AND main_chain_index<=? AND sequence='good' AND is_stable=1 \n\
					LIMIT 1",
					[changed_address, objValidationState.last_ball_mci],
					function(rows){
						cb2(rows.length > 0);
					}
				);
				break;
```
