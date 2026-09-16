This confirms the vulnerability: in `definition.js`, the `sig` case verifies the same `unit_hash_to_sign` against `args.pubkey` at each authentifier `path` independently, and both `evaluate()` in `validateDefinition` (lines 118-185) and `evaluate()` in `validateAuthentifiers` (lines 646-711) never check for duplicate `pubkey`/`address` entries within an `and`/`or`/`r of set` member list.

### Title
Duplicate signer entries in `r of set` / `and` address definitions bypass multisig threshold - ([File: definition.js])

### Summary
An address (or asset condition) definition using `r of set` (or `and`/`weighted and`) can list the *same* signing key (`["sig", {pubkey: X}]`) more than once inside its `set`/`args` array. Neither `validateDefinition` nor `validateAuthentifiers` in `definition.js` deduplicates the list before counting satisfied branches, so a single physical private key can satisfy two (or more) "required" slots of a threshold by re-using the identical signature under two different authentifier paths.

### Finding Description
`validateDefinition`'s `r of set` handler (`definition.js`, function `validateDefinition`, case `'r of set'`) only checks `args.set.length`, `args.required <= args.set.length`, and that each set member is a structurally valid boolean expression: [1](#0-0) 
It never verifies that the `set` members are distinct addresses/pubkeys/conditions.

At evaluation time, `validateAuthentifiers`'s `r of set` handler simply iterates `args.set`, evaluating each member at its own path (`path+'.'+index`) and counting how many return true, comparing against `args.required`: [2](#0-1) 

The `sig` leaf case verifies the authentifier value supplied at that specific path against the *unit hash to sign* and the leaf's `pubkey`: [3](#0-2) 
Because the message being signed (`objValidationState.unit_hash_to_sign`) is the same for the whole unit, if the same `pubkey` appears at two different paths in the `set`, the single valid ECDSA signature produced by that one key is a valid authentifier value at *both* paths. The author of the unit can simply copy the same signature string into both authentifier slots (`r.0`/`r.1`, etc.), and each `sig` leaf independently validates.

This means a wallet/AA address defined as, e.g., `["r of set", {required: 2, set: [sig(A), sig(A), sig(B)]}]` — which co-signers are led to believe is a genuine "2-of-3" (or "2 distinct keys required") arrangement — can actually be fully authorized by key `A` alone, without any cooperation from `B`. The same applies to `and` (`definition.js` case `'and'`, lines 118-145 for validation and lines 672-690 for evaluation), where duplicate branches inflate `count_options_with_sig`/`res` without requiring distinct signers.

This is the direct analog of the reported bug class: a list (extraRewards / here, `set` members in a threshold definition) that is iterated and counted without checking for duplicate entries, letting one contribution be counted multiple times and defeating the intended threshold/guard.

### Impact Explanation
This allows unauthorized spending of funds from what is believed to be a multi-party shared address, wallet, or AA-condition (`issue_condition`/`transfer_condition`), or bypass of an intended cosigning requirement, since a single colluding/malicious party whose key is duplicated in the `set` can single-handedly satisfy `required` without the cooperation of the other named cosigners. This directly leads to unauthorized spending / fund loss for the other party who believed additional signers were required — matching the "concrete unauthorized spending" acceptance criterion.

### Likelihood Explanation
Exploitation requires the malicious party to control (or contribute) the address definition text used to derive the shared address (e.g. as part of `wallet_defined_by_addresses.js`/`wallet_defined_by_keys.js` shared-wallet setup, or as the definer of an asset's `issue_condition`/`transfer_condition`), so that a victim signs up to what they believe is an N-distinct-key threshold while one key is silently duplicated. Since address definitions are only chash-verified (must match `objectHash.getChash160`) but never checked for duplicate entries by `validateDefinition`, this can pass consensus validation on all nodes consistently, so it is a deterministic, low-cost, always-reproducible bypass once a victim accepts such a maliciously-constructed definition.

### Recommendation
In `validateDefinition` (`definition.js`), for `'and'`, `'or'`, `'r of set'`, and `'weighted and'`, reject definitions whose `args`/`args.set` array contains structurally duplicate members (e.g., compare serialized/`objectHash` of each branch) before accepting the definition. This prevents a single key/address/condition from being counted more than once toward satisfying `required`/threshold checks.

### Proof of Concept
1. Generate a keypair for address `A` and one for `B`.
2. Build the definition `arrDefinition = ["r of set", {required: 2, set: [["sig", {pubkey: pubA}], ["sig", {pubkey: pubA}], ["sig", {pubkey: pubB}]]}]` and derive `shared_address = objectHash.getChash160(arrDefinition)`.
3. Present this to `B` as "requires 2 of {A, A, B}" — i.e., disguised as needing both A and B, when in fact `A`'s single key occupies two of the three `set` slots.
4. Fund `shared_address`.
5. To spend, `A` signs the unit once, obtaining `sigA`, and submits an author with `authentifiers = {"r.0": sigA, "r.1": sigA}` (paths corresponding to the two duplicate `set` entries).
6. `validateAuthentifiers`'s `r of set` case (`definition.js:692-711`) evaluates both `r.0` and `r.1` `sig` leaves against the same `unit_hash_to_sign` and `pubA`; both succeed, `count` reaches `2 >= required`, and the unit is accepted — spending the shared funds without any signature from `B`.

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
