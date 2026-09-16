ecdsaSign uses the secp256k1 library's default deterministic nonce (RFC6979), so signing the same `unit_hash_to_sign` with the same private key always produces the same signature bytes. Combined with the missing duplicate-branch check in `r of set` / `weighted and`, this confirms the analog is real and exploitable with a single signing operation reused across multiple authentifier paths.

### Title
Duplicate branches in `r of set` / `weighted and` address definitions let a single key satisfy a multi-key threshold, enabling unauthorized spending from a "multisig" address - (File: `definition.js`)

### Summary
`Definition.validateDefinition()` validates `r of set` and `weighted and` operators by checking only the *count* of positive branches (or their weight sum) against `required`, but never checks that the branches (and thus the underlying keys/addresses they reference) are distinct. Anyone who controls the definition of an address (e.g., a member creating a shared/joint address, or an AA author defining a spending condition) can put the same `sig`/`address`/`hash` leaf twice (or more) inside the `set`, so that a single private key can satisfy two or more "required" slots, defeating the multisig guarantee the other participants rely on. This mirrors the reported `LibUbiquityPool.addCollateralToken()` class of bug: an entity is inserted into a set/collection without a uniqueness check, and that duplication is later double-counted against an invariant (there: collateral index count; here: the multisig `required` threshold).

### Finding Description
In `definition.js`, the definition-structure validator does not reject duplicate set members: [1](#0-0) 
The same lack of a uniqueness check exists for `weighted and`: [2](#0-1) 

At signature-verification time, `validateAuthentifiers()` independently evaluates each branch of the set by its own path and simply counts how many branches are satisfied: [3](#0-2) 
and for `weighted and`: [4](#0-3) 

The `sig` leaf verification checks only that `assocAuthentifiers[path]` is a valid ECDSA signature over `unit_hash_to_sign` for the given `pubkey` — it does not require that different paths carry cryptographically distinct proofs: [5](#0-4) 

Because `ecdsaSign()` (secp256k1 library) is deterministic (RFC6979 nonce derivation), signing the same `unit_hash_to_sign` with the same private key twice always yields byte-identical signatures: [6](#0-5) 

Consequently, if a definition contains `["r of set", {required: 2, set: [["sig",{pubkey:A}], ["sig",{pubkey:A}], ["sig",{pubkey:B}]]}]` (key `A` duplicated), the holder of key `A` alone can supply the same signature string under both paths `r.0` and `r.1` and satisfy `required: 2` without any cooperation from the holder of key `B`. The same applies to `weighted and` (duplicate the highest-weight branch) and to duplicated `["address", X]` branches referencing the same inner address/key. No part of `validateDefinition`, `validateAuthentifiers`, or the shared-address creation flow (`wallet_defined_by_addresses.js`'s `validateAddressDefinitionTemplate`/`handleNewSharedAddress`, and `extractAddressPathsFromDefinition`) checks for or rejects duplicate leaves/paths pointing to the same key: [7](#0-6) [8](#0-7) 

By contrast, the codebase does enforce uniqueness elsewhere for a conceptually similar list — the asset `attestors` list must be sorted/strictly increasing (implicitly rejecting duplicates): [9](#0-8) 
which shows the project is aware that duplicate members in "authorization sets" are problematic, but this protection was not applied to `r of set` / `weighted and`.

### Impact Explanation
A user (or device) participating in the creation of a joint/multisig address, or an AA author defining an internal spending/authorization condition using `r of set`/`weighted and`, can craft (or get others to accept) a definition whose `set` secretly contains a duplicated branch for a key they control. Once the address is funded by counterparties who believe it requires cooperation of `required` distinct signers, the malicious party can move funds unilaterally by resubmitting their own (deterministic) signature under two or more paths. This is a concrete unauthorized-spending / theft-of-funds scenario for any address whose security model relies on requiring multiple *distinct* keys, which is the entire purpose of `r of set` and `weighted and`.

### Likelihood Explanation
The bug is directly reachable by any address definer using standard oscript address-definition syntax — no special privileges, hub/node cooperation, or race conditions are required. It requires only that a victim (or victims) accept a maliciously-constructed shared-address definition (a normal part of the multi-device wallet flow in `wallet_defined_by_addresses.js`) without independently auditing it for duplicate branches — a non-obvious check that ordinary users are unlikely to perform, since the definition size/structure otherwise looks like a legitimate `2-of-3` or weighted scheme.

### Recommendation
In `validateDefinition()`, when validating `r of set` and `weighted and` (and ideally `or`/`and`), reject sets that contain structurally identical branches (e.g., compare `JSON.stringify` of each normalized branch, or specifically disallow repeated `sig`/`address`/`hash` leaves referencing the same `pubkey`/address/hash within the same set). This mirrors the existing duplicate-prevention pattern already used for `attestors` (`checkAttestorList`), and should be versioned behind an upgrade MCI consistent with other consensus-affecting validation changes in this file (e.g., `pemCurvesFixMci`-style gating).

### Proof of Concept
1. Key holder `A` (device/participant in a joint wallet) proposes/accepts a shared address with definition:
   `["r of set", {required: 2, set: [["sig",{pubkey:A}], ["sig",{pubkey:A}], ["sig",{pubkey:B}]]}]`
   (the duplication of `A` is not obvious from a cursory look and is not rejected by `validateAddressDefinitionTemplate`/`validateDefinition`).
2. Counterparty `B` (and possibly others) fund this address believing 2 independent keys are required to spend.
3. To spend, `A` signs the unit's `unit_hash_to_sign` once with their private key, producing signature `S` (deterministic ECDSA, RFC6979).
4. `A` submits `S` as `author.authentifiers["r.0"]` and again as `author.authentifiers["r.1"]`.
5. In `validateAuthentifiers`, both `r.0` and `r.1` verify successfully against `pubkey=A` using `ecdsaSig.verify`, `count` reaches `2 >= required`, and the unit passes `validateDefinition`/`validateAuthentifiers`, allowing `A` alone to move the funds.

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

**File:** definition.js (L713-732)
```javascript
			case 'weighted and':
				// ['weighted and', {required: 15, set: [{value: boolean_expr, weight: 10}, {value: boolean_expr, weight: 20}]}]
				var weight = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb3){
						index++;
						evaluate(arg.value, path+'.'+index, function(arg_res){
							if (arg_res)
								weight += arg.weight;
							cb3(); // check all members, even if required minimum already found
							//(weight < args.required) ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(weight >= args.required);
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

**File:** signature.js (L11-14)
```javascript
function sign(hash, priv_key){
	var res = ecdsa.ecdsaSign(hash, priv_key);
	return Buffer.from(res.signature).toString("base64");
};
```

**File:** wallet_defined_by_addresses.js (L338-375)
```javascript
// Returns a map of signing_path -> address for every ["address", ...] leaf in the definition
function extractAddressPathsFromDefinition(arrDefinition) {
	var result = {};
	function traverse(arr, path) {
		if (!Array.isArray(arr) || arr.length < 2) return;
		var op = arr[0];
		var args = arr[1];
		switch (op) {
			case 'or':
			case 'and':
				if (Array.isArray(args))
					for (var i = 0; i < args.length; i++)
						traverse(args[i], path + '.' + i);
				break;
			case 'r of set':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i], path + '.' + i);
				break;
			case 'weighted and':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i].value, path + '.' + i);
				break;
			case 'address':
				result[path] = args;
				break;
			case 'hash':
				result[path] = 'secret';
				break;
			case 'in merkle':
				result[path] = ''; // empty address
				break;
		}
	}
	traverse(arrDefinition, 'r');
	return result;
}
```

**File:** wallet_defined_by_addresses.js (L481-516)
```javascript
function validateAddressDefinitionTemplate(arrDefinitionTemplate, from_address, handleResult){
	try{
		var assocMemberDeviceAddressesBySigningPaths = getMemberDeviceAddressesBySigningPaths(arrDefinitionTemplate);
	}
	catch (e) {
		return handleResult("failed to get member device addresses of new shared address: " + e.toString());
	}
	var arrDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
	if (arrDeviceAddresses.length < 2)
		return handleResult("less than 2 member devices");
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
	
	var params = {};
	// to fill the template for validation, assign my device address (without leading 0) to all member devices 
	// (we need just any valid address with a definition)
	var fake_address = device.getMyDeviceAddress().substr(1);
	arrDeviceAddresses.forEach(function(device_address){
		params['address@'+device_address] = fake_address;
	});
	try{
		var arrFakeDefinition = Definition.replaceInTemplate(arrDefinitionTemplate, params);
	}
	catch(e){
		return handleResult(e.toString());
	}
	var objFakeUnit = {authors: [{address: fake_address, definition: ["sig", {pubkey: device.getMyDevicePubKey()}]}]};
	var objFakeValidationState = {last_ball_mci: MAX_INT32};
	Definition.validateDefinition(db, arrFakeDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult(null, assocMemberDeviceAddressesBySigningPaths);
	});
}
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
