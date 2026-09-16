### Title
Unbounded, timelock-free redefinition of a referenced address retroactively changes spending conditions on already-received funds - (File: definition.js)

### Summary
An ocore address definition can delegate part of its spending authority to another address via the `['address', other_address]` operator. Unlike a self-contained multisig condition, this operator is **not evaluated once and frozen** — it is re-resolved every time the outer definition/asset condition is evaluated, always against the *current, latest stable* definition of `other_address`. Any owner of `other_address` can therefore unilaterally change the effective spending/authentication logic of every address, asset issuance condition, or AA-referencing structure that points to them, at any time after funds have already been sent to the dependent address, with no upper bound on what the new definition can allow and no timelock protecting counterparties who already deposited funds.

### Finding Description
`validateDefinition()` and `validateAuthentifiers()` in `definition.js` both implement the `'address'` op by calling `storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, ...)`, which always looks up whatever definition is currently stable for `other_address` at the time the referencing unit is being validated: [1](#0-0) [2](#0-1) 

The lookup itself, `readDefinitionChashByAddress`, explicitly resolves to the *latest* definition change stable at or before `max_mci`, not the definition that existed when the dependent address/condition was created or when counterparties deposited funds: [3](#0-2) 

This dynamic re-resolution is a deliberate, documented design choice — the code comment on `validateAuthentifiers` states it must "re-validate the definition every time... in case a referenced address was redefined": [4](#0-3) 

Because there is no bound on what a new definition can specify and no delay beyond ordinary DAG stability (achieved as soon as the redefinition unit becomes stable, which any user can accelerate by attaching their own units), the owner of `other_address` can effectively act like the `setFee` admin in the referenced report:
- They can weaken or strip authentication that a counterparty relied on when depositing/locking funds into a shared/escrow address whose definition includes `['address', other_address]`, or into an asset condition that references `other_address` (e.g. via `attested`/`seen definition change`/`address` combinations).
- Because this happens post-deposit, on already-settled outputs, it mirrors the BribeVault issue of the fee/parameter being alterable for funds that are already committed.
- Because achieving stability can be fast and is entirely under the changer's control (they choose when to post the redefinition and how quickly to bury it), the change can effectively "frontrun" a counterparty's own spend attempt from the dependent address.

### Impact Explanation
Any wallet, escrow, vesting, multisig, or asset-issuance construct that relies on `['address', X]` (or `'seen definition change'`/`'has definition change'` with `new_definition_chash: 'any'`) to delegate authority to a counterparty address is exposed: that counterparty can retroactively redefine their own address to remove co-signing requirements, add new signers, or otherwise alter the condition, gaining unilateral/unauthorized ability to spend funds that other parties already deposited in good faith relying on the original definition — a concrete unauthorized-spending / fund-loss scenario, analogous to the admin exploiting `setFee` on already-deposited BribeVault funds.

### Likelihood Explanation
Medium. Exploitation requires that some other party actually deposits value into an address/definition that delegates trust to an address the attacker controls via `['address', X]` (a legitimate and documented ocore pattern used by shared/multisig addresses and escrow-style contracts), and that the depositing counterparty did not anticipate that `X`'s owner can change `X`'s definition after the fact. This is a realistic, common usage pattern (shared addresses composed from member addresses) rather than a contrived edge case, but it does require a specific composition pattern to be present, not every address is affected.

### Recommendation
- When a definition or asset condition references another address via `['address', X]`, consider pinning/snapshotting the referenced definition's chash at the time the outer definition/condition is created (or at deposit time) rather than always resolving to the latest stable definition, at least optionally (e.g. an `['address', X, pinned_chash]` variant).
- Alternatively, enforce a mandatory timelock/delay between a definition-change unit becoming stable and it taking effect for `'address'`-referencing evaluations, so that depositors relying on an existing definition have a window to react (spend out, or refuse to deposit) before a redefinition becomes effective, similar to the timelock recommended for `setFee` in the original report.
- Document explicitly, in-protocol validation warnings or wallet UX, that using `['address', X]` grants `X`'s current owner ongoing, unbounded control over the referencing definition's evaluation, not just control frozen at set-up time.

### Proof of Concept
1. Attacker A creates address `X` with an initial definition `["sig", {pubkey: A_pub}]`.
2. Victim V creates a shared/escrow address `S` with definition `["and", [["address", X], ["sig", {pubkey: V_pub}]]]` (or similar), believing that spending from `S` always requires A's current, presumably fixed, key plus V's signature.
3. V (or a third party) sends funds to `S`, believing the multisig-like protection holds indefinitely.
4. A posts an `address_definition_change` for `X`, changing X's definition to something A fully controls alone, e.g. `["sig", {pubkey: A_new_pub}]}` — this is unrestricted; per `definition.js`'s `'address'` handling, whatever is currently stable for `X` is used when `S` is evaluated: [5](#0-4) .
5. Once A's redefinition unit is stable, any subsequent validation of a unit spending from `S` re-resolves `X`'s condition to the new definition (per `storage.readDefinitionChashByAddress` always returning the latest stable `definition_chash` for `X`) [6](#0-5) , changing what previously required agreement into whatever A's new key/logic allows — potentially enabling A to spend V's already-deposited funds from `S` in ways the original agreement never authorized.

### Citations

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

**File:** definition.js (L1449-1453)
```javascript
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
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
