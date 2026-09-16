### Title
Missing duplicate-member check in `r of set` / `weighted and` address definitions allows sub-threshold control of multisig addresses - (File: definition.js)

### Summary
The reported bug class is a missing duplication check on an array of "accounts" that lets one entry be counted multiple times, defeating the intended multi-party control. The direct analog in `ocore` is the address-definition validator in `definition.js`, which validates the `set` array of `r of set` and `weighted and` operators but never checks that the members of `set` are distinct. Combined with the fact that signature verification is path-independent, this lets a single private key satisfy several "distinct" slots of a supposed M-of-N multisig address.

### Finding Description
`validateDefinition()` validates `r of set` and `weighted and` definitions purely on array length, `required` bounds, and per-element well-formedness — it never rejects duplicate members of `args.set`: [1](#0-0) [2](#0-1) 

At authentication time, `validateAuthentifiers()`'s `sig` handler verifies the signature only against the *unit hash* and the declared `pubkey`, with no binding to the specific signing `path`: [3](#0-2) 

Because `ecdsaSig.verify(objValidationState.unit_hash_to_sign, signature, args.pubkey)` does not depend on `path`, the exact same signature string can legally be supplied under two (or more) different `authentifiers` paths as long as both paths correspond to `sig` leaves with the same `pubkey`. If the `set` array of an `r of set`/`weighted and` definition contains two entries that reference the same key (directly via `sig`, or indirectly via `address` pointing to the same inner address), one real signer can satisfy `count_options_with_sig`/`weight_of_options_with_sig` for both duplicate slots with a single signature, so the number of *distinct* keys actually needed to reach `required` is lower than what co-signers believe when they agree to the address definition.

This mirrors the higher-level helper code used by wallets to build such multisig templates (`createMultisigWallet`, `getMemberDeviceAddressesBySigningPaths`, `getDeviceAddressesBySigningPaths`), none of which check for duplicate device addresses/pubkeys either: [4](#0-3) [5](#0-4) [6](#0-5) 

Notably, other parts of the codebase *do* enforce uniqueness where duplication would be dangerous — e.g. unit authors and signed-message authors must be strictly sorted (which forbids duplicates): [7](#0-6) [8](#0-7) 
and `has equal`/`has one equal` explicitly rejects duplicate fields: [9](#0-8) 
This shows the project is aware of and normally protects against this exact class of "array can contain duplicates" issue, but the protection is missing specifically for `r of set` / `weighted and` set members.

### Impact Explanation
An address (in particular, a shared/multisig address created cooperatively by several device owners via `wallet_defined_by_keys.js` / `wallet_defined_by_addresses.js`, or any address whose definition a user is asked to trust as "N-of-M") can be constructed with duplicate `set` members that all resolve to the same underlying key. Other legitimate co-signers, believing the definition requires `required` distinct approvals, unknowingly accept an address that one colluding member (who controls two or more duplicated slots) can help unlock with fewer real approvals than intended. This directly enables unauthorized spending / loss of funds from the shared address, since the actual security threshold silently drops below what was agreed. This is a fund-loss-class issue affecting private-key/address definitions reachable by any unprivileged party proposing a shared address definition.

### Likelihood Explanation
Exploitation requires only that the attacker be one of the parties proposing/approving the definition of a shared address (a normal, unprivileged capability via `create_new_shared_address` / wallet definition templates), and that the other cosigners do not manually audit the raw `["r of set", {...}]` array (or `["weighted and", {...}]`) for duplicate `sig`/`address` entries — something no client-side or protocol-side validation currently checks. This is a realistic path since address definitions are JSON structures composed programmatically and are not typically manually reviewed element-by-element by non-technical co-signers.

### Recommendation
In `definition.js`, when validating `r of set` and `weighted and` (and similarly `or`/`and` where relevant), reject definitions whose `set`/`args` array contains duplicate leaves that resolve to the same authentication key/address (e.g., duplicate `["sig", {pubkey}]`, `["hash", {hash}]`, or `["address", addr]` entries). At minimum, add a structural-equality duplicate check on `args.set` elements in the `r of set` and `weighted and` branches of `validateDefinition()`, and add equivalent duplicate checks in `getMemberDeviceAddressesBySigningPaths` / `getDeviceAddressesBySigningPaths` so that wallet-creation flows also refuse templates with duplicated device/pubkey members.

### Proof of Concept
1. Alice and Bob agree to create a 2-of-3 shared address using `createMultisigWallet`/`create_new_shared_address` with device set `[Alice, Bob, Mallory]`, `required = 2`.
2. Mallory (a normal participant, not privileged) proposes the underlying definition as:
   `["r of set", {required: 2, set: [["sig",{pubkey: Alice_pk}], ["sig",{pubkey: Mallory_pk}], ["sig",{pubkey: Mallory_pk}]]}]`
   i.e. Mallory's own pubkey is inserted twice into the 3-member set instead of Bob's key (or Bob's key is one of the duplicates in a more disguised template).
3. `validateAddressDefinitionTemplate`/`validateDefinition` accepts this definition — nothing in `definition.js` lines 147-185 rejects duplicate `set` members.
4. To spend, Mallory only needs to produce **one** valid signature with `Mallory_pk` and copy the same signature string into the authentifiers at both duplicate paths (e.g. `r.1` and `r.2`), since `ecdsaSig.verify` in `definition.js` lines 734-754 checks only `(unit_hash_to_sign, signature, pubkey)`, not the path.
5. `count_options_with_sig` reaches `2` (paths `r.1` and `r.2`) even though only one distinct real key (Mallory's) signed, satisfying `required = 2` — Mallory alone spends funds from what other parties believed was a genuine 2-of-3 (or 2-distinct-party) address.

### Citations

**File:** definition.js (L147-159)
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
```

**File:** definition.js (L187-199)
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

**File:** wallet_defined_by_keys.js (L260-266)
```javascript
function createMultisigWallet(xPubKey, account, count_required_signatures, arrDeviceAddresses, walletName, isSingleAddress, handleWallet){
	if (count_required_signatures > arrDeviceAddresses.length)
		throw Error("required > length");
	var set = arrDeviceAddresses.map(function(device_address){ return ["sig", {pubkey: '$pubkey@'+device_address}]; });
	var arrDefinitionTemplate = ["r of set", {required: count_required_signatures, set: set}];
	createWallet(xPubKey, account, arrDefinitionTemplate, walletName, isSingleAddress, handleWallet);
}
```

**File:** wallet_defined_by_keys.js (L436-483)
```javascript
function getDeviceAddressesBySigningPaths(arrWalletDefinitionTemplate){
	function evaluate(arr, path){
		var op = arr[0];
		var args = arr[1];
		if (!args)
			return;
		var prefix = '$pubkey@';
		switch (op){
			case 'sig':
				// ignore static keys. We do not assume all keys are pubkey@device_address
				if (!args.pubkey || args.pubkey.substr(0, prefix.length) !== prefix)
					return;
				var device_address = args.pubkey.substr(prefix.length);
				assocDeviceAddressesBySigningPaths[path] = device_address;
				break;
			case 'hash':
				if (!args.hash || args.hash.substr(0, prefix.length) !== prefix)
					return;
				var device_address = args.hash.substr(prefix.length);
				assocDeviceAddressesBySigningPaths[path] = device_address;
				break;
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
			case 'definition template':
				throw Error(op+" not supported yet");
			// all other ops cannot reference device address
		}
	}
	var assocDeviceAddressesBySigningPaths = {};
	evaluate(arrWalletDefinitionTemplate, 'r');
	return assocDeviceAddressesBySigningPaths;
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

**File:** validation.js (L1134-1140)
```javascript
	var prev_address = "";
	for (var i=0; i<arrAuthors.length; i++){
		var objAuthor = arrAuthors[i];
		if (objAuthor.address <= prev_address)
			return callback("author addresses not sorted");
		prev_address = objAuthor.address;
	}
```

**File:** signed_message.js (L145-155)
```javascript
	var prev_address = "";
	var the_author;
	for (var i = 0; i < authors.length; i++){
		var author = authors[i];
		if (!ValidationUtils.isNonemptyObject(author))
			return handleResult("author must be a non-empty object");
		if (!ValidationUtils.isValidAddress(author.address))
			return handleResult("not valid address");
		if (author.address <= prev_address)
			return handleResult("author addresses not sorted");
		prev_address = author.address;
```
