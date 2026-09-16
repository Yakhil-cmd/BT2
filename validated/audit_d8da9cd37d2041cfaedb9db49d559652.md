### Title
Hidden unauthorized-spending branch in shared-address / multisig-wallet definition templates accepted without full-tree verification - (File: `wallet_defined_by_addresses.js`)

### Summary
When a device proposes a new shared address (or a new HD multisig wallet), the recipient's wallet validates the proposed `address_definition_template` by (1) walking the tree to collect the *recognized* `$address@device` placeholders as "members", and (2) checking that the resulting filled-in definition is syntactically valid oscript via `Definition.validateDefinition`. Neither step verifies that every signature-granting leaf of the boolean tree is actually one of the enumerated member placeholders. A malicious co-signer can therefore embed an extra, unrelated spending branch (e.g. a hard-coded `sig` or `cosigned by` leaf under an `or`) that lets the attacker spend the "shared" funds alone, while the victim's approval flow only reports the innocuous, expected members.

### Finding Description
`getMemberDeviceAddressesBySigningPaths` in [1](#0-0)  only recurses into `or`, `and`, `r of set`, `weighted and`, and only records `address` leaves whose value matches the `$address@device` placeholder pattern. Any other leaf type appearing anywhere in the boolean tree — a literal `sig` with a hard-coded attacker pubkey, a `hash` leaf, a `cosigned by` leaf referencing an address the attacker already controls, or a literal (non-templated) `address` — is silently ignored: the `switch` has no matching case and the function simply returns for that node without error and without adding anything to `assocMemberDeviceAddressesBySigningPaths`.

`validateAddressDefinitionTemplate`, [2](#0-1) , uses only this incomplete member list to perform its safety checks: it requires at least 2 members, requires "my device address" to be among them, and requires the sender's address to be among them. It then fills in the template with a single fake address for *all* recognized `$address@` placeholders and calls `Definition.validateDefinition`, which only checks oscript syntactic validity/complexity — it does not, and cannot, tell the caller "this definition also allows spending through path X that has nothing to do with the declared members."

Consequently, an attacker (a paired device / correspondent, i.e., an unprivileged peer able to reach this code path via the `create_new_shared_address` handler at [3](#0-2) ) can construct a template such as:

```
["or", [
  ["and", [["address","$address@victim_device"], ["address","$address@attacker_device"]]],
  ["sig", {"pubkey": "<attacker's own fixed pubkey, unrelated to the multisig members>"}]
]]
```

- `getMemberDeviceAddressesBySigningPaths` walks into the `and` branch and finds two members: `victim_device` and `attacker_device` (2 members, satisfying the `>=2` check). It never inspects the sibling `sig` leaf.
- The victim's own device address is present (it is one of the two "and" members), and the sender's (attacker's) device address is also present, so both membership checks in `validateAddressDefinitionTemplate` pass.
- `replaceInTemplate` + `Definition.validateDefinition` only validate that the *filled* definition is syntactically legal oscript (an `or` of an `and` of two `sig`s and a bare `sig`) — which it is, so validation succeeds.
- The UI-facing event `eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths)` (fired from [4](#0-3) ) hands the wallet application only the enumerated (incomplete) member map, which typically drives what is shown to the user for approval — the victim is led to believe this is a normal 2-of-2 shared address.

Once the victim approves and the address is created via `handleNewSharedAddress`/`addNewSharedAddress`, [5](#0-4) , funds sent to that address can be spent unilaterally by the attacker at any time using only the hidden `sig` branch, without any cosignature from the victim, since the on-chain spending-condition evaluator (`definition.js` `validateAuthentifiers`/`evaluate`, e.g. the `or` handling at [6](#0-5) ) is a faithful, unrestricted interpreter of whatever oscript was actually embedded in the definition — it has no notion of "declared members" and will happily authorize a spend through the `sig` branch alone.

The same class of gap exists in the analogous HD-wallet flow, `wallet_defined_by_keys.js` `validateWalletDefinitionTemplate` (used for `create_new_wallet` offers) [7](#0-6) , which likewise derives its "device addresses" from recognized `$pubkey@device` placeholders and validates only syntactic correctness of the filled-in template.

### Impact Explanation
This yields concrete unauthorized spending: a paired device (untrusted counterparty in a proposed multisig arrangement) can craft a definition template that passes all of ocore's automated sanity checks and superficially looks like a legitimate N-of-M shared address, while actually containing an independent, unilateral spending path for the attacker. Once the victim (a genuinely privileged party — the owner of one of the "member" keys) approves the offer, believing multiple signatures are required, the attacker can drain any funds later deposited to that shared address without the victim's knowledge or cosignature. This is a direct violation of the core guarantee of the shared-address/multisig feature and results in fund loss, matching the "unauthorized spending" impact bar.

### Likelihood Explanation
The attack requires no special privilege beyond being a paired device that can send wallet-protocol messages (`create_new_wallet` / `create_new_shared_address`) — something any correspondent/paired device can already do. It requires only that the victim approve the offer through their wallet UI without manually decoding the raw oscript definition (which is exactly the trust model these convenience helpers exist to avoid forcing on users). The victim-side code performs no exhaustive verification that every leaf of the boolean tree corresponds to a declared, expected member, so the attack is reliably reproducible against any wallet relying on `validateAddressDefinitionTemplate` / `validateWalletDefinitionTemplate` to vet incoming proposals.

### Recommendation
When validating a definition/wallet template, walk the *entire* boolean tree and require that every terminal spending-condition leaf (`sig`, `hash`, `address` with a literal value, `in merkle`, `cosigned by`, etc.) either resolves to one of the declared member placeholders or is explicitly rejected. Reject any template containing leaves that are not derived from the enumerated `$address@device` / `$pubkey@device` placeholders, and surface the fully-resolved boolean structure (not just the member list) to the user-approval UI so any additional independent spending path is visibly flagged rather than silently accepted.

### Proof of Concept
1. Attacker (device B) sends `create_new_shared_address` to victim (device A) with:
   `address_definition_template = ["or", [["and", [["address","$address@A"], ["address","$address@B"]]], ["sig", {"pubkey": "<B's separate, undeclared pubkey>"}]]]`.
2. `validateAddressDefinitionTemplate` computes `assocMemberDeviceAddressesBySigningPaths = {"r.0.0": A, "r.0.1": B}`, passes the `length>=2`, "my device included", and "sender included" checks, and `Definition.validateDefinition` accepts the filled template as valid oscript.
3. Device A's UI shows a normal-looking "2-of-2 shared address with B" approval dialog and the user approves.
4. The resulting `shared_address`'s real definition is `or(and(sig_A, sig_B), sig_B_alt)`; attacker signs any spending unit with `B_alt` alone and it is validated as authorized by `definition.js`'s standard `or`/`sig` evaluation, draining funds without A's cosignature.

### Citations

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

**File:** wallet.js (L197-212)
```javascript
			case "create_new_shared_address":
				// {address_definition_template: [...]}
				if (!ValidationUtils.isArrayOfLength(body.address_definition_template, 2))
					return callbacks.ifError("no address definition template");
				walletDefinedByAddresses.validateAddressDefinitionTemplate(
					body.address_definition_template, from_address, 
					function(err, assocMemberDeviceAddressesBySigningPaths){
						if (err)
							return callbacks.ifError(err);
						// this event should trigger a confirmatin dialog, user needs to approve creation of the shared address and choose his 
						// own address that is to become a member of the shared address
						eventBus.emit("create_new_shared_address", body.address_definition_template, assocMemberDeviceAddressesBySigningPaths);
						callbacks.ifOk();
					}
				);
				break;
```

**File:** definition.js (L118-145)
```javascript
		switch(op){
			case 'or':
			case 'and':
				if (!Array.isArray(args))
					return cb(op+" args must be array");
				if (args.length < 2)
					return cb(op+" must have at least 2 options");
				var count_options_with_sig = 0;
				var index = -1;
				async.eachSeries(
					args,
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
						cb(null, op === "and" && count_options_with_sig > 0 || op === "or" && count_options_with_sig === args.length);
					}
				);
				break;
```

**File:** wallet_defined_by_keys.js (L485-515)
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
