### Title
Weighted multisig definitions allow a single signer to inflate effective weight and bypass the intended co-signer threshold - ([File: definition.js])

### Summary
The Ronin report describes an attack where a validator-set "weight" value was manipulated so that withdrawals passed threshold checks without genuine independent multi-signature approval. `ocore` implements an analogous weighted-threshold primitive (`weighted and`, and the related `r of set`) in address/asset spending conditions. Neither `validateDefinition` nor `validateAuthentifiers` in `definition.js` verifies that the individual elements of a `weighted and`/`r of set` set are distinct (different signers). An address definer (or a party proposing a shared multisig address via `wallet_defined_by_addresses.js`) can list the same underlying signer (same `sig` pubkey or the same nested `address`) multiple times with different weight labels, so that a single real signature satisfies the "required" weight/count that other co-signers believe represents multiple independent approvals.

### Finding Description
`validateDefinition`'s handling of `weighted and` only checks structural constraints — that `required` and each `weight` are positive integers, capped after `pemCurvesFixMci`, and that `required <= total_weight`: [1](#0-0) 

It never checks that the `value` expressions (e.g., `["sig", {pubkey: ...}]` or `["address", ...]`) inside `args.set` are unique. The same applies to `r of set`: [2](#0-1) 

At authentication time, `validateAuthentifiers` evaluates each set element independently and sums the weight of elements whose signature check passes: [3](#0-2) 

A single ECDSA signature over the unit hash is valid under a given pubkey regardless of which JSON path in the definition tree it is attached to (`assocAuthentifiers` is keyed by path, not by pubkey), and the `sig` leaf check is purely `ecdsaSig.verify(unit_hash_to_sign, signature, pubkey)`: [4](#0-3) 

Consequently, one signer whose key/`address` is duplicated across multiple weighted-set entries can supply the identical signature at each corresponding authentifier path and have their weight counted multiple times, satisfying `args.required` alone even though the address was represented (and agreed to by co-signers) as requiring contributions from several distinct parties.

This is directly reachable through the shared-address creation flow in `wallet_defined_by_addresses.js`. When a device proposes a new shared address, `handleNewSharedAddress` only checks that (a) the address hash matches the definition, (b) each declared signer address is syntactically valid, (c) the address at each definition leaf matches the claimed signer for that path, and (d) every leaf has a signer — it never checks for duplicate signer addresses across different weighted/`r of set` leaves: [5](#0-4) [6](#0-5) 

A malicious co-signer can thus construct (and get other members to approve, since nothing flags the duplication) a `weighted and`/`r of set` definition where their own address/key occupies two or more "slots" with combined weight ≥ `required`, letting them unilaterally move funds out of what other participants believe is a genuine N-of-M shared wallet — mirroring the Ronin bug class of "weight manipulation defeats multisig threshold."

### Impact Explanation
This allows unauthorized spending from what is represented as a multi-party (weighted or r-of-set) address: a minority (or single) key-holder can meet the `required` threshold alone, draining funds without the cooperation of the other intended co-signers. This is a concrete unauthorized-spending / fund-loss condition, matching the Critical/High severity bar (direct theft of custodied funds from a shared address), analogous to the $12M Ronin loss caused by weight manipulation bypassing the multisig check.

### Likelihood Explanation
Exploitation requires the attacker to be one of the parties defining/proposing the shared address definition (or crafting their own address's weighted definition) — a role reachable by any wallet user via the normal `create_new_shared_address` / `new_shared_address` device-message flow, with no special privileges (network, hub, or key-leak access) needed. The other co-signers must fail to notice the duplicate signer in the JSON definition tree (which is not surfaced to them explicitly and is not flagged by any validation code), making this a plausible, though not automatic, real-world scenario for opaque/complex definitions.

### Recommendation
- In `definition.js`, when validating `weighted and` and `r of set` (and generally in any construct combining independent branches meant to represent distinct authorizers), detect and reject duplicate leaf signer material (same `sig` pubkey, same `hash`, or the same resolved `address`) across the elements of `args.set`.
- In `wallet_defined_by_addresses.js`'s `handleNewSharedAddress`/`extractAddressPathsFromDefinition`, explicitly check that the set of addresses/pubkeys bound to distinct signing paths within any weighted/`r of set` construct are pairwise distinct, and surface a clear error/warning to the UI if duplication is detected before a user approves participation in a shared address.

### Proof of Concept
1. Attacker (address A) proposes a shared address defined as:
   `["weighted and", {required: 100, set: [{value:["sig",{pubkey:A}], weight:60}, {value:["sig",{pubkey:A}], weight:60}, {value:["sig",{pubkey:B}], weight:40}]}]`
   presented to co-signer B as "needs both A and B to jointly reach weight ≥100" (A alone only nominally has 60, B has 40 — looks like cooperation is required).
2. B approves via `handleNewSharedAddress` (`wallet_defined_by_addresses.js:378-415`) — no duplicate-signer check exists, so validation passes and the shared address is created with `validateAddressDefinitionTemplate`/`Definition.validateDefinition`, which also does not reject duplicate set values (`definition.js:187-232`).
3. To spend, A creates a unit and signs it once with their private key, and inserts the identical signature at both authentifier paths corresponding to A's two set entries (`r.0` and `r.1`).
4. In `validateAuthentifiers`, each occurrence independently verifies via `ecdsaSig.verify` (`definition.js:734-754`) and contributes its weight, so weight sums to 60+60=120 ≥ 100, and the unit is accepted as fully authorized — despite B never having cosigned.

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

**File:** definition.js (L187-232)
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

**File:** wallet_defined_by_addresses.js (L439-479)
```javascript
function getMemberDeviceAddressesBySigningPaths(arrAddressDefinitionTemplate){
	function evaluate(arr, path){
		var op = arr[0];
		var args = arr[1];
		if (!args)
			return;
		switch (op){
			case 'or':
			case 'and':
				for (var i=0; i<args.length; i++)
					evaluate(args[i], path + '.' + i);
				break;
			case 'r of set':
				if (!ValidationUtils.isNonemptyArray(args.set))
					return;
				for (var i=0; i<args.set.length; i++)
					evaluate(args.set[i], path + '.' + i);
				break;
			case 'weighted and':
				if (!ValidationUtils.isNonemptyArray(args.set))
					return;
				for (var i=0; i<args.set.length; i++)
					evaluate(args.set[i].value, path + '.' + i);
				break;
			case 'address':
				var address = args;
				var prefix = '$address@';
				if (!ValidationUtils.isNonemptyString(address) || address.substr(0, prefix.length) !== prefix)
					return;
				var device_address = address.substr(prefix.length);
				assocMemberDeviceAddressesBySigningPaths[path] = device_address;
				break;
			case 'definition template':
				throw Error(op+" not supported yet");
			// all other ops cannot reference device address
		}
	}
	var assocMemberDeviceAddressesBySigningPaths = {};
	evaluate(arrAddressDefinitionTemplate, 'r');
	return assocMemberDeviceAddressesBySigningPaths;
}
```
