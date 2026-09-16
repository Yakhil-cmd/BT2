### Title
Duplicate Members in `r of set` / `weighted and` Address Definitions Let a Single Key Satisfy Multiple Required Slots - ([File: definition.js])

### Summary
`validateDefinition` in `definition.js` validates the structure of `r of set` and `weighted and` operators (required count, set length, weights) but never checks that the members of the `set` are distinct. [1](#0-0)  This mirrors the reported Aloe `enrollCourier` bug class: an actor is allowed to occupy multiple "slots" in a scheme that is meant to represent independent participants, with no uniqueness enforcement.

### Finding Description
When validating an `r of set` definition, `validateDefinition` only checks `args.required`, `args.set` length, and that `required <= set.length`; it recurses into each set member independently without deduplicating identical `["address", X]` or `["sig", {pubkey: P}]` leaves. [1](#0-0)  The same absence of a uniqueness check applies to `weighted and`. [2](#0-1) 

At authentication time (`validateAuthentifiers`), each set member is evaluated independently by path, and the count of satisfied members is compared to `args.required`: [3](#0-2) 

For a `sig` leaf, the check is `ecdsaSig.verify(objValidationState.unit_hash_to_sign, signature, args.pubkey)` — this verification depends only on the fixed `unit_hash_to_sign` and the `pubkey`, not on the authentication `path` itself. [4](#0-3)  Consequently, if the *same* pubkey (or the same inner `address`, per the `address` case at lines 774-800) appears twice inside one `r of set`, the definition owner can supply the identical valid signature string at two different authentifier paths (`r.0` and `r.1`) and have both slots counted as "satisfied," even though only one distinct key ever signed.

This is directly analogous to the reported bug: just as `enrollCourier` never checked whether `msg.sender` already held a courier id, letting one address occupy every id and "own" the whole scheme, `validateDefinition` never checks whether an address/pubkey already occupies a slot in the `set`, letting one key occupy every slot and satisfy any threshold `required` up to `set.length`.

### Impact Explanation
An `r of set` (or `weighted and`) definition is meant to model independent co-signers reaching a quorum (e.g., `{required: 2, set: [A, B, C]}` implies at least 2 out of 3 *distinct* parties must agree). If duplicate entries for the same key/address are permitted, a single controlling party can construct (or be handed, in a shared/multisig address scenario) a definition where the "quorum" is nominally N-of-M but is actually satisfiable by one signer alone, because the same signature counts toward multiple slots. This breaks the security assumption that funds/authority protected by such a definition require multiple independent approvals, enabling unauthorized single-party spending from what appears to be a properly co-signed address, and could be used to trick counter-parties in shared-address / multisig-wallet setups (`wallet_defined_by_addresses.js`, `wallet_defined_by_keys.js`) who verify definitions assuming distinct member addresses per signing path.

### Likelihood Explanation
Any unprivileged unit poster can craft an address definition with duplicated entries in `r of set`/`weighted and` and have it accepted, since `validateDefinition` performs no uniqueness check on `args.set` members. [1](#0-0)  The attack requires only constructing a definition and signing a unit with it — no special privileges. The main constraint is social/protocol: other legitimate co-signers must be convinced the address represents a genuine multi-party quorum, which is realistic in the wallet-sharing flow where `handleNewSharedAddress` validates paths against the definition but does not itself reject duplicate member addresses across signing paths. [5](#0-4) 

### Recommendation
In `validateDefinition`'s `r of set` and `weighted and` cases, reject sets that contain duplicate leaves that resolve to the same signing key/address (e.g., duplicate `["address", X]`, `["sig", {pubkey: P}]`, or other authentifier-bearing terminals) so that `required` truly reflects the number of distinct authenticating parties needed. Additionally, `handleNewSharedAddress` / `validateAddressDefinitionTemplate` in the wallet modules should verify that member addresses assigned to different signing paths are distinct before accepting a shared address definition.

### Proof of Concept
1. Generate a single keypair with pubkey `P`.
2. Construct definition: `["r of set", {required: 2, set: [["sig", {pubkey: P}], ["sig", {pubkey: P}]]}]`.
3. Submit this as an address definition in a unit's `authors[i].definition`; `validateDefinition` accepts it because it only checks `required <= set.length` (2 <= 2) with no duplicate check. [1](#0-0) 
4. To spend from this address, sign the `unit_hash_to_sign` once with the private key for `P`, and supply that identical signature string at both authentifier paths `r.0` and `r.1`.
5. `validateAuthentifiers`'s `r of set` handler evaluates each path independently; both `sig` checks pass via `ecdsaSig.verify` (path-independent verification), so `count` reaches 2 and `count >= args.required` is satisfied with a single real signature. [3](#0-2) [4](#0-3)

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

**File:** wallet_defined_by_addresses.js (L377-415)
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
}
```
