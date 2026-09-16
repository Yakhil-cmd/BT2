Confirmed: the SQL comment at `initial-db/byteball-sqlite-light.sql:176` explicitly documents "might not be defined in definitions yet (almost always, it is not defined)" for `definition_chash`, and `validation.js:1719-1745` (`case "address_definition_change"`) only checks `isValidAddress(payload.definition_chash)` — a format-only check — never that a resolvable/known definition (matching hash preimage) exists or will exist. This is the closest, in-scope analog to the report's "missing validation of `_owner` could indefinitely lock owner role."

### Title
Unvalidated `definition_chash` in `address_definition_change` can permanently lock an address and freeze its funds - (File: validation.js)

### Summary
The `UniswapV3Factory` report flags that an unchecked `_owner`/`setOwner` argument can be set to an unrecoverable value (e.g. `address(0)` or a wrong address), permanently locking the privileged owner role and requiring an expensive redeploy. The direct analog in ocore is the `address_definition_change` message, which lets any address holder change the definition (i.e., the signing/authorization logic) bound to that address by supplying only a `definition_chash` (a hash commitment) — without ever proving, at validation time, that a resolvable definition exists for that chash. Validation only performs a shape check (`isValidAddress`), exactly mirroring the report's "missing validation of the privileged-role argument."

### Finding Description
`validateInlinePayload` handles `case "address_definition_change"` in [1](#0-0) . The only content check on the new definition commitment is:
```
if (!isValidAddress(payload.definition_chash))
    return callback("bad new definition_chash");
```
This is purely a base32/format/length check, not a check that the poster actually knows a definition array that hashes to `payload.definition_chash`, or that such a definition has ever been revealed anywhere. The schema itself documents this gap: `address_definition_changes.definition_chash` is annotated "might not be defined in definitions yet (almost always, it is not defined)" [2](#0-1) .

Once this change becomes stable, `storage.readDefinitionChashByAddress` treats it as the address's new binding definition commitment, superseding the old, working definition [3](#0-2) . Any future unit authored from that address must supply an `author.definition` whose `objectHash.getChash160(...)` equals this stored chash, checked in `validateAuthor`/`validateDefinition` (`ifDefinitionNotFound` path) [4](#0-3) . If the chash committed to does not correspond to any definition the address owner actually possesses the preimage for (e.g., a mistyped hash, a hash copied from an unrelated source, or a hash for which the owner never actually derived a matching signing definition), no future unit can ever satisfy `readDefinitionByAddress`'s `ifFound`/`ifDefinitionNotFound` resolution with a valid signature, and the address becomes permanently unable to author new units — including any transaction needed to move funds out.

This mirrors the Trail-of-Bits root cause precisely: a role-defining parameter (owner address / definition_chash) is accepted with only superficial format validation, and an incorrect value silently locks the associated privileged capability (spending authority) with no recovery path once stable.

### Impact Explanation
Any address that publishes an `address_definition_change` with a `definition_chash` for which no matching definition can ever be produced becomes permanently unable to sign new units. Because ocore's balance model requires spending inputs to be signed by the address's currently active definition, all base-currency and asset balances held at that address become permanently frozen — unauthorized loss of use of funds with no redeploy or recovery mechanism, matching the "AA fund loss or freezing" / node-disagreement-adjacent impact bar (here specifically fund freezing at the protocol layer). This is reachable by any ordinary, unprivileged address owner without cooperation from witnesses, nodes, or other privileged actors.

### Likelihood Explanation
Likelihood is driven by user/tooling error rather than attacker intent (paralleling the report's own exploit scenario of Alice mistakenly passing `address(0)`): a wallet or script computing `definition_chash` incorrectly (e.g., hashing the wrong definition, or hardcoding a placeholder value) would pass current validation entirely, since no simulation or preimage check occurs at validation time. The lack of any sanity check (e.g., requiring the new definition to be at least referenced/co-revealed, or requiring `has_references`/reachability data) means the class of "typo/logic-bug locks my own address forever" is fully unguarded by protocol validation.

### Recommendation
Add defense-in-depth validation to `validateInlinePayload`'s `"address_definition_change"` handling in [1](#0-0) :
- Where practical, require (or strongly recommend at the wallet-composition layer) that the new definition be co-revealed/verifiable at the time of the change, or that the composer refuse to compose a change unless it can locally recompute the same chash from a definition it holds.
- Consider adding an explicit warning/guard path and/or a two-step "propose then confirm" pattern (analogous to the report's two-step ownership-change recommendation), so a wrong commitment does not take effect irreversibly on the first, single message.
- At minimum, ensure wallet-composition code (`composeDefinitionChangeJoint` in [5](#0-4) ) always derives `definition_chash` from a definition object it has already validated and stored locally, rather than accepting an arbitrary hash string from an external caller.

### Proof of Concept
1. Address `A` currently signs with definition `D0` (`chash160(D0) == A`).
2. `A`'s owner (or a compromised/buggy wallet component) composes and posts a unit containing:
   ```
   { app: "address_definition_change", payload: { definition_chash: "<any 32-byte base32 string not derived from a definition the owner holds>" } }
   ```
3. `validateInlinePayload` accepts this because `isValidAddress(payload.definition_chash)` only checks format [6](#0-5) .
4. Once stable, `readDefinitionChashByAddress` returns this new, unknown chash as `A`'s active definition commitment [3](#0-2) .
5. `A` can never again produce an `author.definition` satisfying `chash160(definition) == new_chash` (no such definition was ever computed/held), so every subsequent unit signed by `A` fails `validateAuthor`'s definition-hash check [7](#0-6) , permanently freezing all funds at address `A`.

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

**File:** initial-db/byteball-sqlite-light.sql (L172-180)
```sql
CREATE TABLE address_definition_changes (
	unit CHAR(44) NOT NULL,
	message_index TINYINT NOT NULL,
	address CHAR(32) NOT NULL,
	definition_chash CHAR(32) NOT NULL, -- might not be defined in definitions yet (almost always, it is not defined)
	PRIMARY KEY (unit, message_index),
	UNIQUE  (address, unit),
	FOREIGN KEY (unit) REFERENCES units(unit)
);
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

**File:** composer.js (L85-87)
```javascript
function composeDefinitionChangeJoint(from_address, definition_chash, signer, callbacks){
	composeContentJoint(from_address, "address_definition_change", {definition_chash: definition_chash}, signer, callbacks);
}
```
