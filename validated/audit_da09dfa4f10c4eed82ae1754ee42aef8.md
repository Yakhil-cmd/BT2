### Title
Address definition can be permanently bricked by an unvalidated `address_definition_change` message - (File: validation.js)

### Summary
The reported bug class is about a critical pointer (Timelock admin) being updated without validating that the new value is actually a controllable, working target, which can permanently disable a contract from ever updating itself again. The closest reachable analog in `ocore` is the `address_definition_change` message: any unprivileged unit poster (single- or multi-authored) can post this message to redirect their own address's future definition to an arbitrary `definition_chash`, and the protocol never checks that this new chash corresponds to a definition the poster (or the address's cosigners) actually possesses or can ever reveal.

### Finding Description
When a unit contains an `address_definition_change` message, `validateInlinePayload` in `validation.js` only checks that `payload.definition_chash` is a syntactically valid base32 address/chash and that there is at most one change per address per unit — it never checks that the new `definition_chash` corresponds to a definition that is knowable or reachable: [1](#0-0) 

The new `definition_chash` is stored in `address_definition_changes` even though "it might not be defined in `definitions` yet (almost always, it is not defined)": [2](#0-1) 

Once this change becomes stable, `readDefinitionChashByAddress`/`readDefinitionByAddress` treat this chash as the address's *only* valid current definition going forward — any future unit from that address must supply an `arrAddressDefinition` whose hash exactly equals this stored chash, or it is rejected in `validateAuthor`'s `validateDefinition`/`ifDefinitionNotFound` branch: [3](#0-2) [4](#0-3) 

This is exactly analogous to the reported bug class: the `Timelock`/`BaseBridgeReceiver` pair required the new "successor" pointer (localTimelock) to be verified as pointing to a controllable entity before committing to it, or the contract becomes unable to ever change it back. Here, the new `definition_chash` is committed to permanently (change is asserted "stable" and enforced going forward) with no verification that a corresponding, knowable definition array will ever be produced. If the poster mistypes the chash, computes it from the wrong template/parameters, or a shared/multisig wallet member proposes a chash whose preimage the actual cosigners never agreed on or don't jointly hold, the address (and any balance/AA-controlled funds it holds) becomes permanently unable to author any further unit, because no future author-supplied definition can ever hash to the wrong committed value.

### Impact Explanation
Any address — including a multi-signature shared address holding pooled user funds — can be permanently locked out of spending its own balance by a single incorrect `address_definition_change` message, exactly mirroring how a `BaseBridgeReceiver` can be bricked by an incorrect `localTimelock`. Because the address can never again produce a valid `unit_authors.definition` matching the erroneous `definition_chash`, all balances/outputs owned by that address become permanently frozen — a concrete case of fund loss/freezing.

### Likelihood Explanation
This requires no special privilege — it is directly reachable by any unprivileged unit poster who controls (or thinks they control) an address, by simply composing and broadcasting one inline message via `composeDefinitionChangeJoint`: [5](#0-4) 
The most realistic trigger is human/tooling error (mistyped or mis-derived chash) or a multi-device/shared-wallet flow where the definition template used to derive the chash is not the one ultimately agreed/held by all cosigners, similar to how the Comet bug arose from operational misconfiguration rather than an external attacker.

### Recommendation
Before allowing an `address_definition_change` message to become part of a stable, enforced state:
- Require (or strongly recommend at the wallet/composer layer) that the new `definition_chash` be derived from and validated against an `arrDefinition` that the poster (and, for shared addresses, all required cosigners) can currently produce/sign — analogous to checking a new Timelock's `admin`/`pendingAdmin` before committing.
- Consider adding a validation step in `validateInlinePayload`'s `address_definition_change` case, or in the wallet-level compose flow (`wallet_defined_by_addresses.js`), that verifies the definition preimage is locally known/reachable and independently verifiable by cosigners prior to broadcast, reducing the chance of an address being locked by an unreachable `definition_chash`.

### Proof of Concept
1. Address `A` (single- or multi-authored) is fully funded.
2. The owner (or a malicious/careless cosigner in a shared-address flow) composes a unit with message `app: "address_definition_change"`, `payload.definition_chash = X`, where `X` is either a mistyped hash or a chash computed from a definition template that the address's actual signers cannot reproduce/sign.
3. The unit is posted and becomes stable; `address_definition_changes` records `X` as address `A`'s new required `definition_chash` per `storage.readDefinitionChashByAddress`.
4. Any future unit from `A` must supply `author.definition` whose `objectHash.getChash160(definition) === X`; since no one holds a definition hashing to `X`, `validateAuthor`'s `validateDefinition` rejects every subsequent attempt, permanently freezing all of `A`'s funds.

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

**File:** validation.js (L1719-1746)
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

**File:** initial-db/byteball-sqlite.sql (L181-190)
```sql
CREATE TABLE address_definition_changes (
	unit CHAR(44) NOT NULL,
	message_index TINYINT NOT NULL,
	address CHAR(32) NOT NULL,
	definition_chash CHAR(32) NOT NULL, -- might not be defined in definitions yet (almost always, it is not defined)
	PRIMARY KEY (unit, message_index),
	UNIQUE  (address, unit),
	FOREIGN KEY (unit) REFERENCES units(unit),
	CONSTRAINT addressDefinitionChangesByAddress FOREIGN KEY (address) REFERENCES addresses(address)
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
