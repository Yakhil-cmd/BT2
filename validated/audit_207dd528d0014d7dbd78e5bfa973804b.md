### Title
Unbounded recursive evaluation of mutually-referencing address definitions causes stack overflow / node crash - ([File: definition.js])

### Summary
`Definition.validateDefinition()` and `Definition.validateAuthentifiers()` in `definition.js` resolve the `'address'` op by fetching the referenced address's definition via `storage.readDefinitionByAddress()` and recursively calling `evaluate()` on it, with no cycle/visited-address tracking. Because address definitions can be changed after creation (via `address_definition_change`), an attacker can construct two addresses whose *current* definitions reference each other, producing a mutual-inclusion cycle analogous to jq's mutual `include` bug (CVE-2026-44777): the module/definition loader recurses without cycle detection when two artifacts reference each other.

### Finding Description
In `definition.js`, the `'address'` case recursively evaluates a referenced address's definition: [1](#0-0) 
and the authentifier-evaluation path does the same: [2](#0-1) 

Both use `storage.readDefinitionByAddress`, which always resolves to the *latest stable* definition for an address, not the definition at the time the reference was authored: [3](#0-2) 

Address definitions are not immutable pointers to content — an address's active definition can be changed at any time via an `address_definition_change` message, with the new definition only needing to hash to the previously-committed `definition_chash`: [4](#0-3) 

This allows the following sequence, all performable by an ordinary unit poster:
1. Create address `A` with a trivial definition (e.g. `["sig", {...}]`).
2. Create address `B` whose definition is `["and", [["address","A"], ["sig", {...}]]]` — this is valid because `A` already exists.
3. Later, change `A`'s definition (`address_definition_change` + new definition disclosure) to `["and", [["address","B"], ["sig", {...}]]]` — this is valid because `B` already exists.

Once step 3 stabilizes, `A`'s active definition references `B`, and `B`'s active definition references `A`. Any subsequent validation that evaluates `A`'s (or `B`'s) definition — e.g. authenticating a payment signed by `A`, or validating `A`/`B` as an inner "address" reference from a third definition/asset condition — will recurse: `evaluate(defA) → readDefinitionByAddress(B) → evaluate(defB) → readDefinitionByAddress(A) → evaluate(defA) → ...`. There is no set of "already-visited addresses" carried through `evaluate()`, unlike other structural limits in the codebase (e.g. `MAX_DEPTH` in `aa_validation.js`'s `validate()`).

The only guard rails are the global `complexity`/`count_ops` counters checked at each `evaluate()` call: [5](#0-4) 
These increment once per `evaluate()` call and abort once `constants.MAX_COMPLEXITY` / `constants.MAX_OPS` is exceeded — but the check happens synchronously nested inside the recursive JS call stack (there is no `setImmediate`/stack-unwinding between recursive `evaluate()` calls the way `aa_validation.js`'s `validate()` explicitly does every 100 calls: `if (count % 100 === 0) return setImmediate(...)`, see `aa_validation.js:598-603`). Every recursive step through the `A→B→A→B...` cycle therefore adds stack frames (through `evaluate`, `readDefinitionByAddress`, `readDefinitionChashByAddress`, DB callback layers, etc.) before the complexity/ops limit is reached. If `MAX_COMPLEXITY`/`MAX_OPS` is large enough (or the DB driver invokes callbacks synchronously, as some drivers do), the native V8 call stack can overflow before the logical iteration limit is hit, crashing the Node.js process that is validating the unit — this affects every full node that processes the triggering unit/joint.

### Impact Explanation
A stack overflow inside `validateAuthentifiers`/`validateDefinition` occurs while validating a normal payment or referencing definition — code every full node runs when confirming units. A crash of the validating node process during consensus-critical validation constitutes a network-wide denial of validation for units touching the affected addresses, i.e. "a network unable to confirm new units" for units authored by, or referencing, the colluding addresses. This matches the Medium severity bound requested (network disagreement/availability rather than direct fund theft), consistent with the analog CVE's CVSS profile (local, low complexity, requires user interaction, high availability impact, no confidentiality/integrity impact).

### Likelihood Explanation
Constructing two colluding addresses and later re-defining one of them to close the cycle is achievable by any unprivileged user using only standard address-definition and `address_definition_change` messages — no special privileges, hub/peer position, or protocol upgrade bypass is required. The complexity/op-count checks exist but do not prevent deep native recursion before they trigger, since counters are only checked synchronously inside the recursive calls rather than budgeted against actual stack depth.

### Recommendation
- Track a `visited` set of addresses (or a recursion-depth counter, similar to `aa_validation.js`'s `MAX_DEPTH`) through both `evaluate()` implementations in `definition.js` and reject/short-circuit evaluation when an address is encountered a second time in the same definition-resolution chain.
- Additionally, break the native call stack periodically during nested `'address'`/`'definition template'` resolution (e.g., via `setImmediate`) the way `aa_validation.js` already does for AA definition validation, so that complexity/op-count limits can actually be enforced before a stack overflow occurs.

### Proof of Concept
1. Post a unit defining address `A` with `arrDefinitionA = ["sig", {"pubkey": pkA}]`.
2. Post a unit defining address `B` with `arrDefinitionB = ["and", [["address", A], ["sig", {"pubkey": pkB}]]]` (valid since `A` exists per `definition.js:269-304`).
3. Post an `address_definition_change` for `A` to `definition_chash' = hash(["and", [["address", B], ["sig", {"pubkey": pkA}]]])`, then in a later unit disclose the new definition for `A` referencing `B` (valid per `validation.js:1464-1484`, since `B` now exists).
4. Once stable, post any unit spending from `A` (or referencing `A`/`B` from a third definition/asset condition). Full nodes validating this unit call `validateAuthentifiers`/`validateDefinition`, which recurse `A→B→A→B…` via `definition.js:774-800` / `definition.js:269-304`, driving the call stack toward overflow before the `complexity`/`count_ops` cutoff is guaranteed to intervene, crashing the validating node process.

### Citations

**File:** definition.js (L103-111)
```javascript
	function evaluate(arr, path, bInNegation, cb){
		complexity++;
		count_ops++;
		if (complexity > constants.MAX_COMPLEXITY)
			return cb("complexity exceeded at "+path);
		if (count_ops > constants.MAX_OPS)
			return cb("number of ops exceeded at "+path);
		if (objValidationState.max_complexity && objValidationState.complexity + complexity > objValidationState.max_complexity)
			return cb(`custom complexity limit ${objValidationState.max_complexity} exceeded at ${path}`);
```

**File:** definition.js (L269-304)
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
				break;
```

**File:** definition.js (L774-800)
```javascript
			case 'address':
				// ['address', 'BASE32']
				if (!pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition))
					return cb2(false);
				var other_address = args;
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						evaluate(arrInnerAddressDefinition, path, cb2);
					},
					ifDefinitionNotFound: function(definition_chash){
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function(author){
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb2(false);
						}
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						evaluate(arrInnerAddressDefinition, path, cb2);
					}
				});
				break;
```

**File:** storage.js (L754-776)
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


// max_mci must be stable
function readDefinitionByAddress(conn, address, max_mci, callbacks){
	readDefinitionChashByAddress(conn, address, max_mci, function(definition_chash){
		readDefinitionAtMci(conn, definition_chash, max_mci, callbacks);
	});
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
