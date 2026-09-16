### Title
`r of set` / `weighted and` address definitions allow duplicate members, letting one key satisfy a multi-party spending quorum - ([File: definition.js])

### Summary
`ocore`'s address-definition system supports multisig-like constructs (`r of set`, `weighted and`) where a quorum (`required`) of member conditions must be satisfied out of a `set` of member conditions/keys. Neither `validateDefinition` nor the authentifier-evaluation logic in `definition.js` rejects a `set` that contains the same leaf condition (e.g. the same `sig`/`pubkey`, or the same nested `address`) more than once. This is the same root cause as the Initia oracle report: a collection of "votes" (here, satisfied set-members) is summed toward a required threshold without deduplicating the underlying identity casting each vote.

### Finding Description
In `validateDefinition`, the `r of set` and `weighted and` cases only check array length, `required` bounds, and recursively validate each member; they never check that the members of `args.set` are distinct: [1](#0-0) [2](#0-1) 

The same absence of dedup exists in the authentifier-satisfaction pass, which simply counts how many members evaluate to true against `count >= args.required` (or accumulated `weight >= args.required`): [3](#0-2) 

Because each `set` member is evaluated at its own path (`path+'.'+index`), a definition can legally contain the identical `["sig", {pubkey: X}]` (or `["address", X]`) twice at two different indices/paths. The holder of the single private key `X` can supply the *same* valid signature twice, once for each duplicate path in `assocAuthentifiers`, and both evaluations independently succeed (`ecdsaSig.verify` only checks hash/sig/pubkey, not path uniqueness), incrementing `count` twice from one real signer.

This directly parallels shared-wallet creation in `wallet_defined_by_addresses.js`. `handleNewSharedAddress` validates that each signing path's claimed address matches the definition and that every definition path has a corresponding signer entry, but never checks that distinct signing paths map to distinct addresses/devices: [4](#0-3) 

So a malicious co-initiator of an "N of M" shared address can construct a definition whose `set` places their own address at 2 (or more) of the M leaf positions, satisfying `required` alone, while an honest co-signer who only inspects the aggregate device/address list (not path-by-path uniqueness) believes real multi-party consent is required.

### Impact Explanation
A shared/multisig address that is advertised and believed to require independent participation of N distinct signers can in fact be spent unilaterally by a single party who occupies ≥`required` duplicate slots in the `r of set`/`weighted and` structure. This is concrete unauthorized spending from a nominally multi-signer wallet — the honest co-signer's approval becomes unnecessary, exactly mirroring the oracle case where one validator's vote counted multiple times to reach the 2/3+1 quorum.

### Likelihood Explanation
Exploitation requires the attacker to be the party proposing/constructing the shared-address definition (an initiator of a shared wallet, or an AA/asset-definition author), which is a normal, unprivileged role reachable by any wallet user proposing a shared address to a correspondent — no special node/network privilege is needed. The honest counterpart would need to fail to manually audit the raw `r of set`/`weighted and` tree for duplicate leaf addresses, since the codebase provides no automated protection.

### Recommendation
- In `validateDefinition`'s `r of set` and `weighted and` cases (`definition.js`), reject a `set` containing duplicate leaf definitions (e.g., duplicate `sig` pubkeys, duplicate `address` chashes, or structurally identical sub-definitions) unless explicitly intended and clearly surfaced to the user.
- In `handleNewSharedAddress` (`wallet_defined_by_addresses.js`), when accepting/validating a proposed shared-address definition, verify that the addresses assigned to distinct signing paths inside `r of set`/`weighted and` blocks are pairwise distinct, and reject/flag proposals that would let a `required` threshold be met by fewer real independent keys than intended.

### Proof of Concept
1. Attacker (device A, holding key `X`) proposes a shared address to honest co-signer (device B) with `arrDefinitionTemplate = ["r of set", {required: 2, set: [["sig", {pubkey: X}], ["sig", {pubkey: X}], ["sig", {pubkey: Y_B}]]}]` (2-of-3, but two of the three slots are attacker's own key `X`).
2. `validateAddressDefinitionTemplate`/`validateDefinition` accept this template — no duplicate-member check exists (`definition.js:147-232`).
3. `handleNewSharedAddress` on device B's side confirms each signing path's address matches supplied signer info and that every path has a signer, but does not verify the two `sig` paths resolve to different real signers (`wallet_defined_by_addresses.js:378-415`). The shared address is created and accepted as a "2 of 3" wallet.
4. To spend, attacker signs the unit hash once with key `X` and places the identical signature string under both duplicate authentifier paths (e.g., `r.0` and `r.1`). `validateAuthentifiers`'s `r of set` case (`definition.js:692-732`) evaluates both paths independently, both succeed, `count` reaches 2 ≥ `required`, and the unit is validated as fully authorized — without any input from honest device B.

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

**File:** definition.js (L692-732)
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
