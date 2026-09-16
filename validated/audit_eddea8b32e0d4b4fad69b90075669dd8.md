Confirmed: `case 'sig'` in `validateAuthentifiers` reads `assocAuthentifiers[path]` and verifies with `ecdsaSig.verify(objValidationState.unit_hash_to_sign, signature, args.pubkey)` — the same `pubkey` at two different `path`s just needs the same message signed twice, which for a fixed `unit_hash_to_sign` produces an identical (or trivially re-derivable) valid signature. This confirms the exploit path.

### Title
Missing uniqueness check on `set` members in `r of set` / `weighted and` definitions allows one key to satisfy multiple required signature slots - (File: definition.js)

### Summary
`Definition.validateDefinition()` validates the `r of set` and `weighted and` boolean-signature templates used in address definitions (and asset spend conditions) but never checks that the elements of `args.set` are distinct. A member (or attacker) proposing a shared/multi-signature address can list the same `["sig", {pubkey: X}]` (or the same nested `["address", A]`) more than once inside the same `set`. Because each set element is evaluated at its own path (`path+'.'+index`), the "required" counter in `evaluate()` is satisfied per-slot, but the actual authentifier check for `sig` only verifies that `ecdsaSig.verify(unit_hash_to_sign, signature, pubkey)` holds for that pubkey — since `unit_hash_to_sign` is the same for the whole unit, the single legitimate key holder can supply the identical signature at every path where its pubkey is duplicated, satisfying an arbitrarily high "required" count with a single private key.

### Finding Description
In `definition.js`'s `validateDefinition`, the `r of set` case only checks array-length and required-count bounds, never uniqueness of `args.set` elements: [1](#0-0) 
The same absence of a uniqueness check exists for `weighted and`: [2](#0-1) 

At authentication time, `validateAuthentifiers`'s `r of set`/`weighted and` handlers simply count how many of the `set` entries evaluate to true against the supplied `assocAuthentifiers`: [3](#0-2) 
And the `sig` leaf just verifies the pubkey against `objValidationState.unit_hash_to_sign` at that specific path, independent of what other paths use the same pubkey: [4](#0-3) 

Because `unit_hash_to_sign` is fixed for the whole unit, a signer can supply the exact same signature bytes at every duplicated path/index that references their pubkey, satisfying `required` counts that were meant to represent independent co-signers. This is structurally identical to the reported Redemptions/TokenRequest bug class: a list (there, redeemable tokens; here, the `set` of signature conditions) is accepted without a uniqueness check, letting one item count multiple times toward an aggregate result.

This directly affects shared-address creation flows in `wallet_defined_by_addresses.js` and `wallet_defined_by_keys.js`, where a proposing co-signer builds the `arrDefinitionTemplate`/`arrDefinition` containing an `r of set`/`weighted and` structure that other devices approve based on the appearance of an "N of M" (or weighted) requirement: [5](#0-4) [6](#0-5) 
Neither `validateAddressDefinitionTemplate` nor `validateWalletDefinitionTemplate` performs any uniqueness check on the member device addresses/pubkeys embedded in the `set`, so nothing prevents a malicious co-signer from duplicating their own address/pubkey slot to reduce the effective quorum while the definition still displays "required: N" to other approving members.

### Impact Explanation
A malicious participant in a shared-address / multisig setup (or an asset's spend condition using `r of set`/`weighted and`) can craft a definition where their own key occupies more than one "slot" of the set. When other co-signers approve what they believe is an N-of-M (or weighted) multisig requiring independent parties, the attacker alone can supply the necessary number of valid authentifiers by reusing their single signature across the duplicated paths, since the signed message (`unit_hash_to_sign`) is identical for all slots in the unit. This allows the attacker to unilaterally spend funds from what was assumed to be a jointly-controlled address — a concrete case of unauthorized spending, matching the accepted impact classes.

### Likelihood Explanation
The attacker only needs to be one of the parties proposing a shared address definition (a normal, unprivileged action available to any wallet user via `createNewSharedAddressByTemplate`/`handleNewSharedAddress`), and no additional infrastructure or trust is required beyond convincing counterparties to approve a template that superficially reads as a legitimate N-of-M or weighted scheme. Detecting the duplication requires other parties to carefully diff every leaf of the `set` array, which is not obviously validated or warned about by the wallet code today.

### Recommendation
In `definition.js`'s `validateDefinition`, when processing `r of set` and `weighted and`, hash/serialize each element of `args.set` (e.g., via `objectHash.getSourceString` or `JSON.stringify`) and reject the definition if any two elements are structurally identical, mirroring the fix applied upstream for Redemptions/TokenRequest (uniqueness check on the accepted list during initialization/definition validation).

### Proof of Concept
1. Attacker generates a single keypair with pubkey `P`.
2. Attacker proposes a shared address definition:
```
["r of set", { "required": 2, "set": [
  ["sig", {"pubkey": "P"}],
  ["sig", {"pubkey": "P"}]
]}]
```
3. Other co-signer(s) approve, believing "required: 2" means two independent keys must sign.
4. `validateDefinition` accepts this definition since no uniqueness check exists on `args.set` (`definition.js:147-185`).
5. When spending, the attacker signs the unit once with `P`, producing signature `S`, and supplies `S` as the authentifier for both `r.0` and `r.1` paths.
6. In `validateAuthentifiers`, both `sig` evaluations at paths `r.0` and `r.1` call `ecdsaSig.verify(unit_hash_to_sign, S, P)`, which succeeds for both, so `count` reaches `2 >= required`, and the unit is treated as fully authorized (`definition.js:692-711`, `734-754`), even though only one private key participated.

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

**File:** wallet_defined_by_keys.js (L485-516)
```javascript
function validateWalletDefinitionTemplate(arrWalletDefinitionTemplate, from_address, handleResult){
	try {
		var arrDeviceAddresses = getDeviceAddresses(arrWalletDefinitionTemplate);
	}
	catch (e) {
		return handleResult("failed to get device addresses of new wallet: " + e.toString());
	}
	if (arrDeviceAddresses.indexOf(device.getMyDeviceAddress()) === - 1)
		return handleResult("my device address not mentioned in the definition");
	if (arrDeviceAddresses.indexOf(from_address) === - 1)
		return handleResult("sender device address not mentioned in the definition");
	
	var params = {};
	// to fill the template for validation, assign my public key to all member devices
	arrDeviceAddresses.forEach(function(device_address){
		params['pubkey@'+device_address] = device.getMyDevicePubKey();
	});
	try{
		var arrFakeDefinition = Definition.replaceInTemplate(arrWalletDefinitionTemplate, params);
	}
	catch(e){
		return handleResult(e.toString());
	}
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32};
	Definition.validateDefinition(db, arrFakeDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult(null, arrDeviceAddresses);
	});
}

```
