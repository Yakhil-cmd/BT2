## Title
Missing uniqueness check on `set` entries in `r of set` / `weighted and` definitions allows a single signer to satisfy a multi-signer threshold - (File: `definition.js`)

### Summary
`Definition.validateDefinition()` validates `r of set` and `weighted and` boolean-expression nodes used in address (and asset) spending-condition definitions, but never verifies that the entries of `args.set` are distinct. The same `["sig", {pubkey: X}]` (or nested `["address", A]`) sub-expression can therefore appear multiple times inside one `set`. Because every `sig` leaf at a distinct path is verified independently against the *same* `unit_hash_to_sign`, a signature produced by a single private key is valid at every path where that key's pubkey appears. The signer only has to copy the identical signature string into the authentifiers object at each duplicated path to satisfy the `required` counter multiple times with one key, exactly the "duplicate entry counted multiple times" root cause described in the reference report (duplicate `plugins` inflating `pluginCount`/balance accounting in `Vault.sol`).

### Finding Description
`validateDefinition()`'s `r of set` branch only checks structural constraints on the set, never uniqueness of its members: [1](#0-0) 

The same absence of a uniqueness check exists for `weighted and`: [2](#0-1) 

At authentifier-verification time, `r of set` simply counts how many child expressions evaluate to `true`, comparing the count against `args.required`: [3](#0-2) 

The leaf `sig` evaluator checks the authentifier present at the *node's own path* against `objValidationState.unit_hash_to_sign`, which is identical for every leaf in the unit (it does not depend on the set index): [4](#0-3) 

Consequently, if the address (or asset spend-condition) owner defines, e.g., `["r of set", {required: 2, set: [["sig",{pubkey:A}], ["sig",{pubkey:A}], ["sig",{pubkey:B}]]}]`, holder of key `A` alone can supply one ECDSA signature over `unit_hash_to_sign` and place it at both `r.0` and `r.1` authentifier paths, satisfying `required=2` without any cooperation from key `B`'s holder. This is functionally identical to the reported `Vault.addPlugin` issue: a collection meant to enumerate *distinct* participants/allowances is not de-duplicated, so one entry is "counted" more than once toward a threshold/allowance calculation.

This is directly reachable by any unprivileged address definer / co-signer of a cooperatively-defined multisig (shared address created via `wallet_defined_by_addresses.js`), since `handleNewSharedAddress`/`createNewSharedAddress` route straight into `Definition.validateDefinition` without any duplicate-set-member check: [5](#0-4) [6](#0-5) 

### Impact Explanation
A shared/multisig address is normally set up so that N *independent* parties must all sign before funds move. If one party proposes (or is duped into helping construct) a definition where their own key is duplicated inside the `set`, that party alone can satisfy the `required` threshold and unilaterally authorize spends from the shared address — bypassing the cooperative-control guarantee the other co-signers believe they have. This is concrete unauthorized spending of funds held at addresses whose control model depends on the true, distinct signer count, caused purely by the missing uniqueness check on `set` members (the same "double counting of duplicate registered entries" root cause as the external report).

### Likelihood Explanation
Reaching this requires only posting/using a self-authored (or collaboratively-authored) address definition — something any wallet user/AA author can already do, with no special privilege. The only extra step is constructing (or tricking co-signers into accepting) a `set` with a repeated `sig`/`address` sub-expression, which is not rejected anywhere in `validateDefinition`.

### Recommendation
In `validateDefinition()`'s `r of set` and `weighted and` branches, reject sets whose elements are structurally identical (e.g., compare `objectHash.getSourceString` or a deep-equality check of each `arg`/`arg.value` against all other entries in the same `set`) so that a definition cannot list the same signer/address twice while claiming a higher effective threshold than the number of distinct signers.

### Proof of Concept
1. Party A (holder of key `A`) proposes a "2-of-2" shared address to party B using template:
   `["r of set", {required: 2, set: [["sig",{pubkey:"$pubkey@A"}], ["sig",{pubkey:"$pubkey@A"}]]}]` — B fails to notice both slots reference the same placeholder/key (or A swaps in the same real pubkey twice after template substitution).
2. `Definition.validateDefinition` accepts this definition; no duplicate-entry check exists (`definition.js` lines 147-184).
3. A signs a unit once with key `A`, producing signature `S` over `unit_hash_to_sign`.
4. A submits authentifiers `{"r.0": S, "r.1": S}`.
5. `evaluate()` for `r of set` independently verifies `S` against pubkey `A` at both `r.0` and `r.1` (`definition.js` lines 734-754), counting `count=2 >= required(2)` (`definition.js` lines 692-711), and the unit validates — A has spent from the "2-of-2" address alone.

### Citations

**File:** definition.js (L147-184)
```javascript
			case 'r of set':
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["required", "set"]))
					return cb("unknown fields in "+op);
				if (!isPositiveInteger(args.required))
					return cb("required must be positive");
				if (!Array.isArray(args.set))
					return cb("set must be array");
				if (args.set.length < 2)
					return cb("set must have at least 2 options");
				if (args.required > args.set.length)
					return cb("required must be <= than set length");
				//if (args.required === args.set.length)
				//    return cb("required must be strictly less than set length, use and instead");
				//if (args.required === 1)
				//    return cb("required must be more than 1, use or instead");
				var count_options_with_sig = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb2){
						index++;
						evaluate(arg, path+'.'+index, bInNegation, function(err, bHasSig){
							if (err)
								return cb2(err);
							if (bHasSig)
								count_options_with_sig++;
							cb2();
						});
					},
					function(err){
						if (err)
							return cb(err);
						var count_options_without_sig = args.set.length - count_options_with_sig;
						cb(null, args.required > count_options_without_sig);
					}
				);
```

**File:** definition.js (L187-233)
```javascript
			case 'weighted and':
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["required", "set"]))
					return cb("unknown fields in "+op);
				if (!isPositiveInteger(args.required))
					return cb("required must be positive");
				if (args.required > 1000 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return cb("required must be <= 1000");
				if (!Array.isArray(args.set))
					return cb("set must be array");
				if (args.set.length < 2)
					return cb("set must have at least 2 options");
				var weight_of_options_with_sig = 0;
				var total_weight = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb2){
						index++;
						if (!isNonemptyObject(arg))
							return cb2("weighted set element must be a non-empty object");
						if (hasFieldsExcept(arg, ["value", "weight"]))
							return cb2("unknown fields in weighted set element");
						if (!isPositiveInteger(arg.weight))
							return cb2("weight must be positive int");
						if (arg.weight > 1000 && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
							return cb2("weight must be <= 1000");
						total_weight += arg.weight;
						evaluate(arg.value, path+'.'+index, bInNegation, function(err, bHasSig){
							if (err)
								return cb2(err);
							if (bHasSig)
								weight_of_options_with_sig += arg.weight;
							cb2();
						});
					},
					function(err){
						if (err)
							return cb(err);
						if (args.required > total_weight)
							return cb("required must be <= than total weight");
						var weight_of_options_without_sig = total_weight - weight_of_options_with_sig;
						cb(null, args.required > weight_of_options_without_sig);
					}
				);
				break;
```

**File:** definition.js (L692-711)
```javascript
			case 'r of set':
				// ['r of set', {required: 2, set: [list of options]}]
				var count = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							if (arg_res)
								count++;
							cb3(); // check all members, even if required minimum already found, so that we don't allow invalid sig on unchecked path
							//(count < args.required) ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(count >= args.required);
					}
				);
				break;
```

**File:** definition.js (L734-754)
```javascript
			case 'sig':
				// ['sig', {algo: 'secp256k1', pubkey: 'base64'}]
				//console.log(op, path);
				var signature = assocAuthentifiers[path];
				if (!signature)
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'secp256k1';
				if (algo === 'secp256k1'){
					if (objValidationState.bUnsigned && signature[0] === "-") // placeholder signature
						return cb2(true);
					var res = ecdsaSig.verify(objValidationState.unit_hash_to_sign, signature, args.pubkey);
					if (!res)
						fatal_error = "bad signature at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported sig algo at path "+path;
					return cb2(false);
				}
				break;
```

**File:** wallet_defined_by_addresses.js (L377-414)
```javascript
// {address: "BASE32", definition: [...], signers: {...}}
function handleNewSharedAddress(body, callbacks){
	if (!ValidationUtils.isArrayOfLength(body.definition, 2))
		return callbacks.ifError("invalid definition");
	if (typeof body.signers !== "object" || Object.keys(body.signers).length === 0)
		return callbacks.ifError("invalid signers");
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: " + JSON.stringify(signerInfo.address));
	}
	const assocDefinitionAddresses = extractAddressPathsFromDefinition(body.definition);
	for (let signing_path in body.signers) {
		const signerInfo = body.signers[signing_path];
		if (assocDefinitionAddresses[signing_path] !== signerInfo.address)
			return callbacks.ifError("signer address at path " + signing_path + " doesn't match definition");
	}
	for (let def_path in assocDefinitionAddresses) {
		if (!body.signers[def_path])
			return callbacks.ifError("no signer for definition address at path " + def_path);
	}
	determineIfIncludesMeAndRewriteDeviceAddress(body.signers, function(err){
		if (err)
			return callbacks.ifError(err);
		validateAddressDefinition(body.definition, function(err){
			if (err)
				return callbacks.ifError(err);
			addNewSharedAddress(body.address, body.definition, body.signers, body.forwarded, callbacks.ifOk);
		});
	});
```

**File:** wallet_defined_by_addresses.js (L518-528)
```javascript
// fix:
// 1. check that my address is referenced in the definition
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
	});
}
```
