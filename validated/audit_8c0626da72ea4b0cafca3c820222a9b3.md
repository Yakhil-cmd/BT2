### Title
A single key/address can be counted multiple times toward a multi-party `r of set`/`weighted and` signature threshold - (File: definition.js)

### Summary
The address definition language allows building an `r of set` (or `weighted and`) spending condition with `required: N` out of a `set` of member conditions (e.g., `["address", A]` or `["sig", {pubkey}]`). Neither `validateDefinition` nor `validateAuthentifiers` verifies that the members of the `set` are distinct parties/keys. The same address or public key can be listed multiple times in the set, and because each set element is authenticated independently at its own signing path, one person holding a single private key can satisfy several "distinct" slots in the same unit, defeating the intended N-of-M multisig threshold — directly analogous to the Sherlock finding where one Pool manager could cast multiple "votes" toward a review threshold that was meant to require multiple distinct managers.

### Finding Description
`validateDefinition`'s `evaluate()` for `r of set` only checks structural constraints (`required` is a positive int ≤ `set.length`, `set.length >= 2`), with no uniqueness check across `args.set` entries: [1](#0-0) 

The actual runtime signature verification in `validateAuthentifiers` counts how many of the `set` members evaluate to true and compares against `args.required`, again with no deduplication by underlying address/pubkey — each set element is checked purely by its `path`: [2](#0-1) 

For a `sig` leaf, verification is simply "does the signature at this path verify against this pubkey and the unit hash": [3](#0-2) 

Because the same `unit_hash_to_sign` is authenticated at every path in the unit, the holder of a single private key can produce two (or more) independent valid ECDSA signatures — one for each occurrence of their pubkey/address in the `set` — placed at different signing paths (`r.0`, `r.1`, etc.) of the same unit. Each occurrence is verified in isolation, so `count` in the `r of set` handler increments once per occurrence, not once per distinct controlling party. An address defined as `["r of set", {required: 2, set: [["address", A], ["address", A], ["address", B]]}]` can therefore be spent by `A` alone signing twice, even though the address was ostensibly designed to require 2-of-3 distinct co-signers (A, A-again, or B).

The `and`/`or`/`weighted and` handlers have the same structural gap: `weighted and` only validates that `weight` and `required` are positive integers and totals are consistent, never that set members are distinct controlling parties.

### Impact Explanation
This breaks the security guarantee of multi-party address definitions (shared wallets, multisig escrows, governance-style addresses) that rely on `r of set`/`weighted and` to require independent authorization from N distinct parties. A single key holder who is placed in the set multiple times (whether intentionally by definition authors expecting extra "weight" safely, or unnoticed by co-signers reviewing a definition) can unilaterally satisfy the whole condition, resulting in unauthorized spending of funds locked behind such an address — a concrete case of unauthorized spending/loss of funds for anyone relying on the multisig-like guarantee.

### Likelihood Explanation
Exploitation requires only posting a normal unit with an address definition of this shape (or a shared address already defined this way) and providing two signatures under the same key at two different signing paths — fully reachable by any unprivileged unit poster/AA/wallet participant who controls or influences the address definition; no special privileges, hub, or node compromise is required.

### Recommendation
When validating `r of set` and `weighted and` (and generally any definition), reject definitions whose `set` contains duplicate leaves that resolve to the same underlying controlling entity (same `sig` pubkey, same `address`, or same nested definition hash) unless explicitly intended, or otherwise require that `required` votes come from structurally distinct member definitions before counting them toward the threshold.

### Proof of Concept
1. Build the address definition:
```json
["r of set", {
  "required": 2,
  "set": [
    ["sig", {"pubkey": "<A's pubkey>"}],
    ["sig", {"pubkey": "<A's pubkey>"}],
    ["sig", {"pubkey": "<B's pubkey>"}]
  ]
}]
```
2. Compute the address `chash` from this definition and fund it.
3. Create a spending unit and, using only A's private key, sign at authentifier paths `r.0` and `r.1` (two distinct valid ECDSA signatures over the same `unit_hash_to_sign`), leaving `r.2` (B's slot) empty.
4. `validateAuthentifiers`'s `r of set` handler evaluates `r.0` → true, `r.1` → true (both verified against the same pubkey via `ecdsaSig.verify`), `r.2` → false, giving `count = 2 >= required (2)`, so the unit is accepted despite B never having authorized the spend — confirming a single party (A) can bypass the intended 2-of-{A,B} threshold.

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
