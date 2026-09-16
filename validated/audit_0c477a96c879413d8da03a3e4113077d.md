### Title
Missing duplicate-entry check in `r of set` / `weighted and` definitions allows one signer's single signature to satisfy a multi-signer threshold - (File: definition.js)

### Summary
`definition.js`'s `validateDefinition()` validates the structural correctness of `r of set` and `weighted and` address-definition operators but never checks that the sub-definitions listed in `args.set` are distinct. Because the corresponding authentifier-matching logic in `validateAuthentifiers()` indexes signatures purely by tree *path* (not by uniqueness of the underlying key/signature), an address owner can construct a definition that nominally requires `M` independent signers out of `N`, but where two or more of the `N` set entries are the *same* `sig` (or other) sub-definition. A single real signature can then be duplicated across those repeated paths, satisfying the `required` count without any additional independent authorization.

### Finding Description
In the definition-structure validator: [1](#0-0) 
the `r of set` case only validates `required`, array length, and recursively evaluates each `args.set[i]`; it never verifies that the elements of `args.set` are pairwise distinct (e.g., different pubkeys/hashes/sub-trees). The same is true for `weighted and`: [2](#0-1) 

By contrast, elsewhere in the very same file a duplicate check *is* performed where the developers considered it necessary, e.g. for `equal_fields` in `has equal`: [3](#0-2) 
showing that the omission for `r of set`/`weighted and` is a gap rather than an intentional design choice.

At authentication time, `validateAuthentifiers()`'s `sig` handler looks up the supplied authentifier purely by the current evaluation `path` and verifies it against the pubkey embedded at that path: [4](#0-3) 
Nothing prevents the same signature bytes (produced by a single real private-key holder) from being supplied at two different paths that happen to reference the same pubkey. The `r of set` counting logic in `validateAuthentifiers()` simply counts how many `args.set[i]` entries evaluate to true and compares against `args.required`: [5](#0-4) 
so a definition such as `["r of set", {required: 2, set: [["sig",{pubkey:A}], ["sig",{pubkey:A}], ["sig",{pubkey:B}]]}]` is accepted by `validateDefinition`, and can later be satisfied by signer `A` alone submitting the same signature twice (once at path `r.0`, once at `r.1`), reaching `count_options_with_sig/count = 2 = required` without cosigner `B`'s participation — exactly the "different-ids-not-checked, single-item-counted-multiple-times" flaw described in the external report, applied to address-authentication set membership instead of NFT token ids.

Shared/multisig addresses in this codebase are collaboratively negotiated between cosigning devices via `wallet_defined_by_addresses.js`; a malicious participant can propose (or a compromised UI can construct) such a definition, and the acceptance path (`handleNewSharedAddress` → `validateAddressDefinition` → `Definition.validateDefinition`) performs no rejection of duplicate set members: [6](#0-5) 

### Impact Explanation
This breaks the fundamental security guarantee of M-of-N multisig/shared addresses. A party who is supposed to need cooperation from other independent cosigners to move funds (e.g. escrow, joint wallet, "2 of 2" or "2 of 3" schemes) can instead spend/move the address's funds unilaterally, as long as the definition contains a duplicated leaf referencing their own key(s) enough times to reach `required`. This is direct unauthorized spending / fund loss for the other cosigners, matching the severity class of the original report (loss of funds from unchecked duplicate entries in a set that should represent distinct commitments).

### Likelihood Explanation
Likelihood is meaningful but conditioned on how the shared-address definition is negotiated: it requires that a malicious (or careless) participant can get the duplicated definition accepted as the group's shared address definition, or that a single actor controls more than one leaf of the tree (a case that is easy to disguise, e.g. embedding the same pubkey under differently-labeled JSON paths of `or`/`and`/`weighted and`/`r of set` combinators). Because none of `validateDefinition`'s branches enforce uniqueness across a set's members, this is exploitable purely with a maliciously/negligently crafted `arrDefinition`, without needing any bug in the DAG, hashing, or signature-verification primitives themselves.

### Recommendation
In `validateDefinition()`'s `r of set` and `weighted and` cases (`definition.js` lines 147-185 and 187-233), reject definitions whose `args.set` elements are not pairwise distinct (e.g., hash-compare each `arg`/`arg.value` sub-tree, analogous to the existing duplicate check used for `equal_fields`). At minimum, disallow duplicate leaf `sig`/`hash` sub-definitions (same `pubkey`/`hash`) from appearing more than once within a single `r of set`/`weighted and`/`or`/`and` set, so that the `required` threshold can only be satisfied by genuinely distinct authenticators.

### Proof of Concept
1. Address owner (or a malicious cosigner during shared-address negotiation) creates definition:
   `["r of set", {required: 2, set: [["sig",{pubkey: A}], ["sig",{pubkey: A}], ["sig",{pubkey: B}]]}]`.
2. `Definition.validateDefinition()` accepts this definition — no check rejects the duplicated `["sig",{pubkey:A}]` entries (`definition.js` lines 147-185).
3. To spend funds from this address, signer `A` alone signs the unit once, producing signature `sigA`.
4. In the unit's `authentifiers`, `sigA` is placed at both `r.0` and `r.1` (the two paths corresponding to the duplicated `A` entries).
5. `validateAuthentifiers()`'s `sig` handler independently verifies `sigA` against pubkey `A` at each path and returns true for both (`definition.js` lines 734-754), so `count_options_with_sig = 2 = required` (`definition.js` lines 692-711), and the unit is accepted as validly signed — without cosigner `B` ever signing.

### Citations

**File:** definition.js (L147-185)
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
				break;
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

**File:** definition.js (L533-543)
```javascript
				var assocUsedFields = {};
				for (var i=0; i<args.equal_fields.length; i++){
					var field = args.equal_fields[i];
					if (typeof field !== 'string')
						return cb("fields must be strings");
					if (["asset", "address", "amount", "type"].indexOf(field) === -1)
						return cb("unknown field: "+field);
					if (assocUsedFields[field])
						return cb("duplicate "+field);
					assocUsedFields[field] = true;
				}
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

**File:** wallet_defined_by_addresses.js (L378-415)
```javascript
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
}
```
