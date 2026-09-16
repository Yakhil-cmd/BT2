### Title
Missing duplicate-entry check in `r of set` / `weighted and` definitions allows a single key to satisfy a multi-signature threshold alone - (File: `definition.js`)

### Summary
`Definition.validateDefinition()` validates the structural correctness of `r of set` and `weighted and` address-definition operators (arity, `required` vs. set size/weight, complexity), but never checks that the elements of `args.set` are distinct. The same underlying spending condition (e.g. the same `["address", X]` or `["sig", {pubkey}]` leaf) can therefore be listed multiple times inside a single set, and each occurrence is counted separately toward the `required` threshold — exactly the same "unique-list assumed, duplicates not rejected" root cause as the reported `Vault.addPlugin` bug, where a duplicated plugin entry is counted twice against a value (`LINK` allowance/balance) that was meant to be tracked per unique entity.

### Finding Description
In `definition.js`, the `evaluate()` function used by `validateDefinition` handles the two threshold operators like this: [1](#0-0) 

and [2](#0-1) 

Both branches only validate `required`/weight bounds and recursively validate each `args.set[i]` element; nowhere is `args.set` checked for duplicate entries (e.g. two elements that are structurally identical, or two `["address", A]` leaves pointing at the same address, or two `["sig", {pubkey}]` leaves with the same key). The corresponding real-time signature counter in `validateAuthentifiers()` mirrors this and also has no de-duplication: [3](#0-2) 

For the `'address'` leaf specifically, satisfying the condition only requires that the referenced address be an author of the unit and that its own definition evaluate to true — it does not require a distinct signature per occurrence in the set: [4](#0-3) 

This means a definition such as `["r of set", {required: 2, set: [["address", A], ["address", A], ["address", B]]}]` is fully valid and, once `A` co-signs the unit and its own definition is satisfied, both occurrences of `["address", A]` count as satisfied — reaching `required: 2` with contribution from only one distinct party (`A`), without any cooperation from `B`.

This is directly reachable by an unprivileged party negotiating a shared/multi-sig address. `wallet_defined_by_addresses.js`'s `handleNewSharedAddress()` — invoked when a peer device proposes a new shared address to be co-signed — validates only that every definition leaf has a matching signer entry and vice versa, and then calls `Definition.validateDefinition` for generic structural checks; it never checks for duplicate address/signer entries across signing paths: [5](#0-4) 

The stricter uniqueness check (`_.uniq(_.values(...))` requiring `arrDeviceAddresses.length >= 2`) exists only in the separate *template*-negotiation path, `validateAddressDefinitionTemplate`: [6](#0-5) 

but a fully resolved (non-template) shared address sent directly through `handleNewSharedAddress`/`createNewSharedAddress` bypasses this uniqueness check entirely.

### Impact Explanation
A malicious co-signer can propose (or accept) a shared/multi-sig address whose `r of set`/`weighted and` definition appears to require independent consent from multiple distinct parties (e.g. "2 of 3"), while secretly occupying two (or more) of the set's slots with their own address/key. Once the victim(s) agree to use the address believing a genuine multi-party threshold protects the funds, the attacker can single-handedly satisfy the threshold and spend/control the shared funds, defeating the multisig security guarantee — a concrete case of unauthorized spending, analogous to the double counting in the reported `Vault` bug where duplicated entries in a should-be-unique list are treated as separate for security-critical accounting (balance vs. signature-threshold accounting here).

### Likelihood Explanation
Reachable by any peer device participating in shared-address setup (a standard, unprivileged wallet flow), requiring no special access — only that a counterparty naively accepts a shared-address proposal without independently auditing the raw `r of set`/`weighted and` structure for duplicate leaves, which ordinary wallet UIs are not expected to surface.

### Recommendation
In `Definition.validateDefinition()` (and the parallel structural checks in `wallet_defined_by_addresses.js`), reject `r of set` and `weighted and` definitions whose `args.set` contains structurally duplicate elements (deep-equal sub-definitions, or more conservatively, duplicate `["address", ...]`/`["sig", ...]`/`["hash", ...]` leaves at different set positions). Apply the same uniqueness requirement currently enforced only for device addresses in `validateAddressDefinitionTemplate` to the non-template `handleNewSharedAddress` path as well, so a distinct real signer/address must back each `set` slot counted toward `required`.

### Proof of Concept
1. Party `A` (attacker) and party `B` (victim) agree to create a shared address intended to require signatures from 2 of 3 members: `A`, `B`, and a supposed third member.
2. `A` crafts the definition `["r of set", {required: 2, set: [["address", A_addr], ["address", A_addr], ["address", B_addr]]}]` and sends it via the `new_shared_address` device message handled by `handleNewSharedAddress`.
3. `handleNewSharedAddress` accepts it: every signing path has a matching signer, `Definition.validateDefinition` only checks arity/complexity, and no duplicate check exists on `args.set`.
4. `B` signs onto the shared address, believing 2 independent members must always cooperate to spend.
5. Later, `A` alone (as the sole author satisfying both `["address", A_addr]` slots) reaches `required: 2` in `validateAuthentifiers`'s `'r of set'` counter and spends from the shared address without `B`'s (or the third member's) cooperation.

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

**File:** definition.js (L692-731)
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

**File:** wallet_defined_by_addresses.js (L481-494)
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
```
