### Title
Composite address definitions dynamically trust a referenced address's *current* definition, letting the referenced signer silently remove policy checks - ([File: definition.js])

### Summary
The reported bug class is: governance holds the ability to swap out validator/policy addresses used by other logic, so a policy check that other code relies on can be removed post-hoc without changing the code that depends on it. In `ocore`, the direct analog is the `'address'` operator in address definitions (composite/"smart" addresses), combined with `address_definition_change`. An address definition can embed another address as a sub-condition (e.g., "trusted validator" address inside a multi-sig/policy wallet), but that embedded condition is not pinned to the definition that existed when the composite address was created — it is re-resolved to whatever definition the referenced address currently has at spend time.

### Finding Description
When validating spending authorization for a composite definition containing the `'address'` operator, ocore looks up the *current* definition of the referenced address via `storage.readDefinitionByAddress`, and recursively evaluates the *latest* definition rather than the one that existed at the time the composite address was set up: [1](#0-0) 

The owner of `other_address` can unilaterally replace their own definition at any time via an `address_definition_change` message, which only requires their own signature and creates a new `definitions`/`address_definition_changes` row — there is no restriction tying it to the definitions that other composite addresses/policies reference: [2](#0-1) [3](#0-2) 

This is architecturally identical to the reported issue: a role (here, the owner/definer of the referenced address, analogous to "governance") can upgrade a value (`definition_chash`) that other trust logic (a multisig/policy composite address referencing them via `'address'`) depends on, thereby weakening or removing the intended policy check without any action from, or awareness of, the party who built the composite policy address. Anyone who built a "policy" address assuming a co-signer/validator address enforces certain conditions (e.g., N-of-N multisig, time locks, attestation requirements) can have that assumption invalidated the moment the referenced address owner redefines their own address to something weaker (e.g., a single key), since evaluation always uses the address's live definition.

The `'has definition change'` / `'seen definition change'` operators reinforce this pattern by explicitly allowing a definition to be written that trusts *any* future definition change of an address (`new_definition_chash === 'any'`), a mechanism purpose-built for this kind of "current-value" dependency: [4](#0-3) [5](#0-4) 

### Impact Explanation
If a user or protocol composes a policy/multisig address that relies on the `'address'` operator to defer part of its spending condition to a separate "validator" or "co-signer" address (a common pattern for shared vaults, escrows, or governance-like multisig setups), the owner of that referenced address can unilaterally weaken their own definition (e.g., remove a required co-signature, lower a threshold, or drop a time-lock) via an ordinary `address_definition_change` message. Because the composite definition is re-evaluated against the *current* definition at spend time (not the one audited/agreed upon at setup), funds locked under the composite address can subsequently be spent under weaker conditions than depositors/co-owners expected — i.e., unauthorized spending of funds that were believed to be protected by the original, stronger policy.

### Likelihood Explanation
This does not require any bug in signature or hash validation — it is intrinsic to how nested `'address'` conditions are (by design) resolved dynamically rather than pinned. Any user who constructs a policy address referencing another address's definition, and any counterparty who deposits funds into it trusting the referenced address's definition to remain the agreed one, is exposed. The referenced address owner needs no special privilege beyond normal address ownership to perform the definition change, and `needToEvaluateNestedAddress`/`arrAuthentifierPaths` gating only affects whether the check is skipped for efficiency, not whether the live definition is used when it is evaluated: [6](#0-5) 

### Recommendation
Consider allowing composite definitions to optionally pin the referenced address's definition to a specific `definition_chash` at composition time (fail closed if it changes), or require explicit re-consent (e.g., co-signature from all beneficiaries of the composite address) before a referenced address's definition change is honored inside a `'address'` sub-condition. At minimum, document explicitly that `'address'` sub-conditions always reflect the *live* definition of the referenced address, so composers are aware trust in this operator is trust in the referenced address owner's future behavior, not a snapshot of current behavior.

### Proof of Concept
1. Alice and Bob jointly create composite address `C` whose definition is `['and', [['sig', {pubkey: Bob_pub}], ['address', Validator_addr]]]`, where `Validator_addr`'s definition at the time is a strict 2-of-2 multisig `['and', [['sig', k1], ['sig', k2]]]` — Alice deposits funds into `C` trusting this strong validator condition.
2. The owner(s) of `Validator_addr` later post an `address_definition_change` unit changing `Validator_addr`'s definition to a trivial `['sig', k1]` (single-key) — this is a normal, unrestricted operation per `validateInlinePayload`'s handling of `address_definition_change`: [7](#0-6) 
3. When funds are later spent from `C`, `validateDefinition`'s `'address'` case resolves `Validator_addr`'s definition fresh via `storage.readDefinitionByAddress`, evaluating the new weak definition instead of the original strict one: [8](#0-7) 
4. As a result, `C` can now be spent under conditions Alice never agreed to (single key instead of 2-of-2), demonstrating that the referenced address's owner effectively "upgraded away" the policy check Alice relied on.

### Citations

**File:** definition.js (L94-100)
```javascript
	function needToEvaluateNestedAddress(path){
		if (!arrAuthentifierPaths) // no signatures, just validating a new definition
			return true;
		if (objValidationState.last_ball_mci < constants.skipEvaluationOfUnusedNestedAddressUpgradeMci) // skipping is enabled after this mci
			return true;
		return pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition);
	}
```

**File:** definition.js (L269-303)
```javascript
			case 'address':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				var other_address = args;
				if (!isValidAddress(other_address))
					return cb("invalid address");
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						console.log("inner address:", arrInnerAddressDefinition);
						needToEvaluateNestedAddress(path) ? evaluate(arrInnerAddressDefinition, path, bInNegation, cb) : cb(null, true);
					},
					ifDefinitionNotFound: function(definition_chash){
					//	if (objValidationState.bAllowUnresolvedInnerDefinitions)
					//		return cb(null, true);
						var bAllowUnresolvedInnerDefinitions = true;
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function (author) {
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb("failed to calc definition hash of co-author "+other_address+": "+e.message);
						}
						if (arrDefiningAuthors.length === 0) // no address definition in the current unit
							return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						needToEvaluateNestedAddress(path) ? evaluate(arrInnerAddressDefinition, path, bInNegation, cb) : cb(null, true);
					}
				});
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

**File:** definition.js (L1179-1197)
```javascript
			case 'has definition change':
				// ['has definition change', ['BASE32', 'BASE32']]
				var changed_address = args[0];
				var new_definition_chash = args[1];
				if (changed_address === 'this address')
					changed_address = address;
				if (new_definition_chash === 'this address')
					new_definition_chash = address;
				cb2(objUnit.messages.some(function(message){
					if (message.app !== 'address_definition_change')
						return false;
					if (!message.payload)
						return false;
					if (new_definition_chash !== 'any' && message.payload.definition_chash !== new_definition_chash)
						return false;
					var payload_address = message.payload.address || objUnit.authors[0].address;
					return (payload_address === changed_address);
				}));
				break;
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
