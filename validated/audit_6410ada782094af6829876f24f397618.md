### Title
Unchecked duplicate leaf definitions in `r of set` / `weighted and` / `and` / `or` allow one key to satisfy a multi-party spending threshold - (File: `definition.js`)

### Summary
`definition.js`'s `validateDefinition` accepts `r of set`, `weighted and`, `and`, and `or` expressions and only validates structural properties of the `set`/`args` array (length, field names, weight bounds), never checking whether two or more entries reference the **same underlying signer** (same pubkey or same sub-address). Because signature verification in `validateAuthentifiers` is performed independently per signing path and depends only on the pubkey at that leaf and the unit hash being signed, a single private key can satisfy multiple `set` entries by reusing the same signature bytes at different paths. This lets one party disguise a shared/multisig address as an N-of-M threshold while secretly controlling `required` (or more) of the weighted votes alone, exactly analogous to the reported `manageOwnedAndDelegated` bug where a caller inflates its own delegated share by supplying the same tokenId multiple times in an unchecked array.

### Finding Description
`evaluate()` in `validateDefinition` (`definition.js:118-234`) validates `or`/`and`/`r of set`/`weighted and` purely structurally: [1](#0-0) [2](#0-1) 

Nowhere in this function (nor anywhere else in `definition.js`) is there a check that the `set`/`args` elements are distinct — unlike other array fields in the codebase that are explicitly protected against duplicates, e.g. `checkAttestorList` (`validation.js:2850-2864`) enforces strict sort order, `earned_headers_commission_recipients` requires `recipient.address <= prev_address` to fail (`validation.js:1101-1126`), the `op_list` system vote requires "sorted and unique" (`validation.js:1861-1873`), and author addresses must be strictly increasing (`validation.js:1128-1140`, `signed_message.js:145-155`). The equal-fields check even explicitly rejects duplicates (`definition.js:534-543`, `"duplicate "+field`). The absence of an analogous check specifically for `r of set`/`weighted and`/`and`/`or` set members is the root cause.

At authentication time, `validateAuthentifiers`'s `sig` handling (evaluated per-path in `r of set`/`weighted and`, see `definition.js:692-732`) verifies the signature supplied for a given path solely against that leaf's own pubkey and the unit's signing hash — it does not track whether the same signature (or same underlying key) has already been "used" at a sibling path: [3](#0-2) 

Because a valid ECDSA signature over `unit_hash_to_sign` is deterministic given the key and message, an attacker holding a single private key referenced twice in the `set` (e.g. `["r of set", {required:2, set: [["sig",{pubkey:A}], ["sig",{pubkey:A}], ["sig",{pubkey:B}]]}]`) can copy the same signature value into both paths' `authentifiers` entries and satisfy `required=2` alone — with no cooperation from key `B`'s holder. The same applies to `weighted and`, where a duplicated pubkey entry lets one key contribute weight from multiple `set` slots, and to nested `["address", addr]` leaves that resolve to the same underlying sub-definition placed at multiple positions.

This is directly analogous to the reported Convergence bug: there, `manageOwnedAndDelegated` accepted arrays of tokenIds with no duplicate check, letting a delegatee add the same tokenId multiple times and multiply their share of `mgCvgVotingPowerPerAddress` at the expense of other delegators. Here, an address (or shared-wallet) definer supplies a `set` array with no duplicate-signer check, letting them multiply their effective share of a multisig's `required` threshold at the expense of the genuinely intended co-signers.

### Impact Explanation
If honest parties (e.g., cosigners collaboratively creating a shared address via `wallet_defined_by_addresses.js`, or any two/more parties relying on a posted address `definition` that is supposed to require independent signatures from `required` distinct keys) do not notice that the malicious proposer's pubkey/sub-address occurs multiple times in the `set`, that party alone can produce a full set of valid authentifiers and spend funds/authorize actions that were meant to require cooperation of the other legitimate signer(s). This is unauthorized spending / de-facto compromise of the intended multisig security guarantee, harming the co-signers who believed their approval was required.

### Likelihood Explanation
Exploitation requires the victim(s) to accept an address definition (a JSON structure) without carefully diffing each leaf's pubkey/sub-address for duplicates — plausible when definitions are large, use nested `weighted and` with several entries, or use blinded/derived pubkeys that are not obviously identical to a casual reviewer. The attack is entirely under the control of the party proposing/using the definition (no privileged access needed) and requires no protocol-level trust bypass; only social/UI-level oversight by the counter-party is needed, which is realistic for wallet software that doesn't warn about duplicate signer leaves.

### Recommendation
In `validateDefinition`'s `evaluate()` handling of `or`, `and`, `r of set`, and `weighted and`, recursively canonicalize/hash each `set`/`args` member (e.g. via `objectHash.getChash160` or a stable JSON hash of the sub-expression) and reject the definition if any two members are structurally identical (same pubkey/sub-address/hash), mirroring the duplicate checks already applied elsewhere in the codebase (`checkAttestorList`, `earned_headers_commission_recipients`, author-address sorting, `equal_fields`). At minimum, warn/reject when the same `pubkey` (in `sig`) or same target `address` (in `address`) appears more than once within a single `set`.

### Proof of Concept
1. Party M (malicious) proposes a "2-of-2"-looking shared address to honest party H using `wallet_defined_by_addresses.js`'s cooperative address-creation flow, with definition:
   `["r of set", {required: 2, set: [["sig", {pubkey: M_pubkey}], ["sig", {pubkey: M_pubkey}], ["sig", {pubkey: H_pubkey}]]}]`
   (three set members, `required: 2`), presented to H as though 2 of 3 real signers are needed.
2. `validateDefinition` accepts this definition because it only checks array length/field types (`definition.js:147-185`), not for duplicate `sig` leaves.
3. H deposits funds into the resulting address, believing both M and H must cooperate (or M plus a third mutually-trusted party) to spend.
4. M signs the spending unit once with `M_pubkey`'s private key, then submits the identical signature value under both `r.0` and `r.1` authentifier paths.
5. `validateAuthentifiers`'s per-path `sig` evaluation (`definition.js:692-732`) independently verifies each path against its own pubkey (`M_pubkey` at both `r.0` and `r.1`) and the shared `unit_hash_to_sign`; both succeed, `count>=required(2)` is satisfied, and the unit validates and spends the funds — without any signature or cooperation from H.

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
