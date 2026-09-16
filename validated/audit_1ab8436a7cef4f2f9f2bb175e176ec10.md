### Title
Duplicate members in `r of set` / `weighted and` address-definition operators are not rejected, allowing a single signer to satisfy a multi-signer threshold - ([File: definition.js])

### Summary
`validateDefinition()` in `definition.js` validates the structural correctness of `r of set` and `weighted and` operators (positive `required`, array length, weight bounds, etc.) but never checks whether the same leaf condition (e.g. the same `["sig", {pubkey}]` or the same `["address", addr]`) appears more than once inside `args.set`. This mirrors the `addPlugin()` bug class: an entity is accepted into a "counted set" without deduplication, so a single underlying entity can be counted multiple times toward a threshold that is supposed to represent independent contributions.

### Finding Description
The `r of set` and `weighted and` validation branches only check array shape/length and numeric bounds: [1](#0-0) [2](#0-1) 

Nowhere in these blocks (nor anywhere else in `validateDefinition`) is there a check that `args.set` elements are distinct. Compare this with `has equal`/`has one equal`, where the analogous field-list is explicitly checked for duplicates: [3](#0-2) 

That duplicate guard exists for `equal_fields` but is absent for `r of set`/`weighted and` set members.

At evaluation time (`validateAuthentifiers`), each set member is evaluated independently by its own `path` (`path+'.'+index`), and the count/weight of members whose sub-branch evaluates true is compared against `required`: [4](#0-3) [5](#0-4) 

Because a `sig` leaf's signature check is verified against the fixed `unit_hash_to_sign` for that unit (not something path-unique), a single real signer whose key is duplicated across N set slots can supply the *same* signature value at each of those N paths and have all N slots count as satisfied — inflating the effective "required" count/weight with only one real signer, exactly the same "count something without deduping identity" flaw that produced double balances in the reported `addPlugin()` bug.

### Impact Explanation
If a shared/multi-party address (e.g. a wallet defined via `wallet_defined_by_addresses.js` templates, or any address whose definition uses `r of set`/`weighted and`) is intended to require signatures from N distinct co-signers, but the definition (or a template-generated definition) ends up listing the same signer's `sig`/`address` leaf more than once inside the set, that one signer can unilaterally satisfy the multisig threshold. This is a concrete unauthorized-spending scenario: funds intended to require independent approval from multiple parties could be moved by a single party, because the "double counting" of one identity inflates the satisfied-requirement tally past `required`.

### Likelihood Explanation
Exploitability depends on getting a definition with duplicate set members accepted. `validateDefinition` is invoked for every new address definition disclosed in a unit (via `validateAuthor`/`validateAuthentifiers`) and for shared-address definitions built from templates in `wallet_defined_by_addresses.js`; nothing in that path rejects duplicate leaves. A malicious co-signer who controls (or influences) the definition template used to create a shared address, or who crafts their own address definition presented as satisfying an `r of set`/`weighted and` policy that other counterparties rely on, can include their own key twice (or more) in the set. Since address definitions are validated purely by structural rules and are otherwise accepted, this requires no special privilege beyond being one of the definition's authors/posters — it is reachable from a normal unit-posting flow.

### Recommendation
In `validateDefinition()`, when validating `r of set` and `weighted and`, compute the canonical (e.g. `JSON.stringify`) form of each `args.set[i]` (or `args.set[i].value` for weighted and) and reject the definition if any two elements are identical, similar to the existing duplicate check used for `equal_fields`:
```js
var seen = {};
for (var i = 0; i < args.set.length; i++) {
    var key = JSON.stringify(args.set[i]); // or args.set[i].value for weighted and
    if (seen[key])
        return cb("duplicate member in " + op);
    seen[key] = true;
}
```
This should be applied before/alongside the existing structural checks in both the `r of set` block (`definition.js:147-185`) and the `weighted and` block (`definition.js:187-233`).

### Proof of Concept
1. Generate a single keypair and its `sig` definition leaf: `defA = ["sig", {pubkey: pubkeyA}]`.
2. Construct an address definition: `["r of set", {required: 2, set: [defA, defA]}]` (or duplicate `defA` inside a `weighted and` set with weights summing to satisfy `required`).
3. Submit this as an address definition (e.g., as a shared address definition or as an author's `definition` field in a unit). `validateDefinition` accepts it because it only checks array length/bounds, not element uniqueness.
4. When spending from this address, the single signer for `pubkeyA` produces one ECDSA signature over `unit_hash_to_sign` and supplies that identical signature string under both authentifier paths (`r.0` and `r.1`) corresponding to the two duplicate set slots.
5. In `validateAuthentifiers`, both `r.0` and `r.1` evaluate to `true` (each independently verifies the same valid signature against the same message), so `count` reaches 2, satisfying `required: 2` — even though only one distinct private key ever signed. The unit validates successfully, allowing a "1-of-1" real signer to spend from what was intended to be a 2-signer (or higher-weight) address.

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
