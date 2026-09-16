### Title
Unbounded attestor-list loop in `attested` address-definition op enables cheap, disproportionate signature-verification cost - (File: definition.js)

### Summary
`ocore`'s address-definition language contains an `attested` operator that lets an address's spending condition reference an arbitrary array of attestor addresses. Unlike the sibling operators `in data feed` and `in merkle`, which explicitly scale the definition's complexity counter by the number of addresses supplied (`complexity += arrAddresses.length-1`), the `attested` operator does not scale complexity with the size of its attestor array in either the definition-validation path or the authentifier (signature) validation path.

### Finding Description
In `definition.js`, `validateDefinition()`'s `evaluate()` function processes the `attested` case: [1](#0-0) 

This loops over `arrAttestors` performing `isValidAddress` checks, but only a single `complexity++` is charged for the whole `attested` node (charged once per call to `evaluate`, at the top of the function): [2](#0-1) 

Compare this to the `in data feed` and `in merkle` cases right next to it, which do scale complexity with the address-array length: [3](#0-2) [4](#0-3) 

Once such a definition is committed as an address's spending condition, every future unit signed by that address must be re-validated through `validateAuthentifiers()`, whose own `attested` handler again passes the full `arrAttestors` array straight to `storage.filterAttestedAddresses()`: [5](#0-4) 

`filterAttestedAddresses` builds a SQL query using the full attestor list every time. Because the array size is not counted against `constants.MAX_COMPLEXITY` / `constants.MAX_OPS` (the mechanisms that bound recursive definition-tree work elsewhere, e.g. in `or`/`and`/`r of set` and in `in data feed`/`in merkle`), an attacker can pack a very large attestor array into an `attested` condition while the definition as a whole still reports low complexity/op counts and passes `evaluate()`'s guard: [6](#0-5) 

The only constraint on `arrAttestors.length` is the physical size of the message payload (bounded by `constants.MAX_UNIT_LENGTH`/message-size fees), which is a one-time cost paid by the attacker when defining/changing the address. After that, every subsequent unit signed by the address — potentially thousands, sent by anyone paying only ordinary per-unit fees — forces every full node in the network to repeat the large-list attestor lookup during ordinary unit validation, with no additional fee charged for the repeated cost.

This differs from the `checkAttestorList()` function used for asset attestors, which explicitly caps the attestor array at `constants.MAX_ATTESTORS_PER_ASSET` and rejects unsorted/duplicate lists: [7](#0-6) 
No equivalent cap exists for the `attested` op's attestor list in address definitions.

### Impact Explanation
Every unit signed by an address using this crafted definition triggers `validateAuthentifiers` → `attested` → `storage.filterAttestedAddresses` with the full, disproportionately large attestor array, which is invoked as part of ordinary consensus-critical unit validation performed by every full node (including in `validateAuthors`/`validateAuthor` inside `validation.js`, the same path reachable from `network.js`'s `handleJoint`/`handleOnlineJoint` for any newly posted unit). This is not a peer/network-layer issue but a computation-cost asymmetry rooted in address-definition/authentifier validation logic reachable by any unprivileged user who defines an address and then posts (or has others pay to post) units signed by it, degrading validation throughput for the whole network on every subsequent spend, i.e., contributing to a node's inability to keep pace confirming new units at a reasonable cost.

### Likelihood Explanation
Medium. The attacker needs to (a) create/define an address whose definition contains an `attested` condition with an inflated attestor array, paying only the normal message-size fee for that one definition unit, and (b) then post ordinary transactions from that address. Because `MAX_COMPLEXITY`/`MAX_OPS` checks do not scale with the attestor list size for this op, and no `MAX_ATTESTORS_PER_ASSET`-style cap exists for it, this bypass is straightforward to construct with a moderately sized unit (limited only by `MAX_UNIT_LENGTH`).

### Recommendation
Add an explicit length cap on `arrAttestors` (e.g., reuse `constants.MAX_ATTESTORS_PER_ASSET` or a dedicated constant) in the `attested` case of `definition.js`'s `validateDefinition()`/`evaluate()`, and/or scale `complexity`/`count_ops` proportionally to `arrAttestors.length` the same way `in data feed` and `in merkle` already do, so the one-time definition cost reflects the recurring per-signature verification cost it imposes on the network.

### Proof of Concept
1. Craft an address definition of the form `['attested', ['this address', [addr_1, addr_2, ..., addr_N]]]` with `N` chosen as large as fits under `constants.MAX_UNIT_LENGTH` for the definition/definition-change message.
2. Submit this as the address's definition (or via `address_definition_change`); `validateDefinition()` accepts it because `complexity`/`count_ops` are incremented only once for the whole `attested` node regardless of `N` (contrast with the `arrAddresses.length-1` complexity addition present in the `in data feed`/`in merkle` cases at `definition.js:401-418` and `445-465`).
3. Post ordinary units signed by this address. Each triggers `validateAuthentifiers()` → case `'attested'` (`definition.js:904-915`) → `storage.filterAttestedAddresses(conn, {arrAttestorAddresses: arrAttestors}, ...)` with the full `N`-sized array, imposing an oversized SQL/lookup cost on every validating node for each of the attacker's subsequent, normally-fee-priced units.

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

**File:** definition.js (L370-388)
```javascript
			case 'attested':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isArrayOfLength(args, 2))
					return cb(op+" must have 2 args");
				var attested_address = args[0];
				var arrAttestors = args[1];
				if (bAssetCondition && attested_address === 'this address')
					return cb("asset condition cannot reference this address in "+op);
				if (!isValidAddress(attested_address) && attested_address !== 'this address') // it is ok if the address was never used yet
					return cb("invalid attested address");
				if (!ValidationUtils.isNonemptyArray(arrAttestors))
					return cb("no attestors");
				for (var i=0; i<arrAttestors.length; i++)
					if (!isValidAddress(arrAttestors[i]))
						return cb("invalid attestor address");
				if (objValidationState.last_ball_mci < constants.attestedInDefinitionUpgradeMci)
					return cb(op+" not enabled yet");
				return cb();
```

**File:** definition.js (L401-418)
```javascript
			case 'in data feed':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!Array.isArray(args))
					return cb(op+" arg must be array");
				if (args.length !== 4 && args.length !== 5)
					return cb(op+" must have 4 or 5 args");
				var arrAddresses = args[0];
				var feed_name = args[1];
				var relation = args[2];
				var value = args[3];
				var min_mci = args[4];
				if (!isNonemptyArray(arrAddresses))
					return cb("no addresses in "+op);
				for (var i=0; i<arrAddresses.length; i++)
					if (!isValidAddress(arrAddresses[i])) // it is ok if the address was never used yet
						return cb("oracle address not valid");
				complexity += arrAddresses.length-1; // 1 complexity point for each address (1 point was already counted)
```

**File:** definition.js (L445-465)
```javascript
			case 'in merkle':
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				if (!Array.isArray(args))
					return cb(op+" arg must be array");
				if (args.length !== 3 && args.length !== 4)
					return cb(op+" must have 3 or 4 args");
				var arrAddresses = args[0];
				var feed_name = args[1];
				var element = args[2];
				var min_mci = args[3];
				if (!isNonemptyArray(arrAddresses))
					return cb("no addresses in "+op);
				for (var i=0; i<arrAddresses.length; i++)
					if (!isValidAddress(arrAddresses[i])) // it is ok if the address was never used yet
						return cb("oracle address not valid");
				complexity += arrAddresses.length-1; // 1 complexity point for each address (1 point was already counted)
```

**File:** definition.js (L904-915)
```javascript
			case 'attested':
				// ['attested', ['BASE32', ['BASE32']]]
				var attested_address = args[0];
				var arrAttestors = args[1];
				if (attested_address === 'this address')
					attested_address = address;
				storage.filterAttestedAddresses(
					conn, {arrAttestorAddresses: arrAttestors}, objValidationState.last_ball_mci, [attested_address], function(arrFilteredAddresses){
						cb2(arrFilteredAddresses.length > 0);
					}
				);
				break;
```

**File:** validation.js (L2850-2864)
```javascript
function checkAttestorList(arrAttestors){
	if (!isNonemptyArray(arrAttestors))
		return "attestors not defined";
	if (arrAttestors.length > constants.MAX_ATTESTORS_PER_ASSET)
		return "too many attestors";
	var prev="";
	for (var i=0; i<arrAttestors.length; i++){
		if (!isValidAddress(arrAttestors[i]))
			return "invalid attestor address: "+JSON.stringify(arrAttestors[i]);
		if (arrAttestors[i] <= prev)
			return "attestors not sorted";
		prev = arrAttestors[i];
	}
	return null;
}
```
