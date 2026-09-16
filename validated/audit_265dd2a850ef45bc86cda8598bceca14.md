### Title
Malicious peer can plant a hidden unilateral spend path in a "shared address" definition, tricking the victim's wallet into treating an attacker-controlled address as trusted joint/multisig - (File: ocore--006/wallet_defined_by_addresses.js)

### Summary
The `ConvexFinance` incident describes users being deceived into approving a malicious contract because the presented approval target did not match what the user actually believed they were authorizing. The reachable analog in `ocore` is the `new_shared_address` device-message flow: a paired correspondent (the AA/contract counterparty analog — any device the wallet is paired with) can send a definition for a "shared address" that is silently accepted and stored as a joint/shared wallet address, while actually containing an independent `["sig", {...}]` (or other authentifier) branch under an `"or"` combinator that lets the attacker spend funds sent to that address alone, without any cooperation from the victim.

### Finding Description
`handleNewSharedAddress` in `wallet_defined_by_addresses.js` validates a peer-supplied shared-address definition only by:
1. Confirming `objectHash.getChash160(body.definition) === body.address` [1](#0-0) 
2. Extracting `["address", ...]` / `["hash", ...]` / `["in merkle", ...]` leaves via `extractAddressPathsFromDefinition` and checking that each such leaf has a matching, well-formed `signers` entry [2](#0-1) [3](#0-2) 
3. Calling `Definition.validateDefinition`, which only checks structural/complexity validity of the oscript expression, not who controls which branch [4](#0-3) 

`extractAddressPathsFromDefinition` walks only `or`, `and`, `r of set`, `weighted and`, `address`, `hash`, and `in merkle` ops [5](#0-4) . It does **not** recurse into or flag a raw `["sig", {pubkey: "..."}]` leaf placed inside an `"or"` branch. Because `signers` only need to cover the paths that `extractAddressPathsFromDefinition` finds, an attacker can craft:

```
["or", [
  ["and", [["address", victim_address], ["address", attacker_address]]],  // looks like a normal 2-of-2 joint address
  ["sig", {pubkey: attacker_pubkey}]                                       // hidden independent spend path
]]
```

This definition passes both the leaf-vs-signer check (only the `"address"` leaves are checked) and `validateDefinition` (a `"sig"` leaf with any pubkey is a perfectly valid definition primitive), so `addNewSharedAddress` stores it as a trusted shared address for the victim device [6](#0-5) . The wallet UI subsequently shows this as a joint/shared address requiring the victim's cooperation, but the attacker alone can sign and spend any funds sent to it via the hidden `"sig"` branch — exactly analogous to a user believing they're interacting with (or funding) a legitimate joint arrangement while a malicious, independently-controlled spend condition has been silently substituted, as in the Convex DNS-phishing incident where the presented approval target didn't match reality.

### Impact Explanation
Any funds a victim (or their counterparties, e.g. in `prosaic_contract`/`arbiter_contract` deposit flows that reuse `wallet_defined_by_addresses.createNewSharedAddress`) sends to such a maliciously-defined "shared" address can be unilaterally drained by the attacker, since the attacker's independent `"or"` branch requires no cooperation from the victim's device. This is concrete unauthorized loss of AA/wallet funds.

### Likelihood Explanation
Exploitation requires only that the attacker be a correspondent (paired device) able to send the standard `new_shared_address` message — a normal, unprivileged wallet-to-wallet interaction used throughout `wallet_defined_by_addresses.js`, `prosaic_contract.js`, and `arbiter_contract.js`. No hub, node, or network-level compromise is needed; the attacker crafts the definition themselves and can present the resulting address as a shared/multisig address for a legitimate-looking business/contract interaction.

### Recommendation
In `extractAddressPathsFromDefinition` (and the validation performed by `handleNewSharedAddress`), enumerate and require an explicit, victim-approved signer entry for every leaf capable of independently satisfying the definition — including `sig`, `hash`, and any other authentifier primitive — not just `address`/`hash`/`in merkle`. Additionally, the wallet should refuse (or explicitly flag to the user) any `"or"`-combined definition branch that does not route through a leaf mapped to a known/expected co-signer, so a hidden unilateral spend path cannot be silently accepted as part of a "shared" address.

### Proof of Concept
1. Attacker pairs with victim's wallet device (normal correspondent pairing).
2. Attacker sends a `new_shared_address` message with:
   - `address` = chash160 of the malicious definition below
   - `definition` = `["or", [["and", [["address", VICTIM_ADDR], ["address", ATTACKER_ADDR]]], ["sig", {pubkey: ATTACKER_PUBKEY}]]]`
   - `signers` = only entries for the `"and"` branch's two `"address"` leaves (paths `r.0.0`, `r.0.1`)
3. `handleNewSharedAddress` computes the chash160 match, validates only the `"address"` leaves against `signers`, and calls `Definition.validateDefinition`, which accepts the well-formed `"sig"` leaf without objection.
4. `addNewSharedAddress` stores the address as a legitimate shared address in the victim's wallet DB.
5. Victim (or their business counterparty in a contract flow) sends funds to this address believing 2-of-2 cooperation is required.
6. Attacker independently signs and spends the funds using the `"sig"` branch, without any victim involvement. [7](#0-6) [2](#0-1)

### Citations

**File:** wallet_defined_by_addresses.js (L239-267)
```javascript
function addNewSharedAddress(address, arrDefinition, assocSignersByPath, bForwarded, onDone){
//	network.addWatchedAddress(address);
	db.query(
		"INSERT "+db.getIgnore()+" INTO shared_addresses (shared_address, definition) VALUES (?,?)", 
		[address, JSON.stringify(arrDefinition)], 
		function(){
			var arrQueries = [];
			for (var signing_path in assocSignersByPath){
				var signerInfo = assocSignersByPath[signing_path];
				db.addQuery(arrQueries, 
					"INSERT "+db.getIgnore()+" INTO shared_address_signing_paths \n\
					(shared_address, address, signing_path, member_signing_path, device_address) VALUES (?,?,?,?,?)", 
					[address, signerInfo.address, signing_path, signerInfo.member_signing_path, signerInfo.device_address]);
			}
			async.series(arrQueries, function(){
				console.log('added new shared address '+address);
				eventBus.emit("new_address-"+address);
				eventBus.emit("new_address", address);

				if (conf.bLight){
					db.query("INSERT " + db.getIgnore() + " INTO unprocessed_addresses (address) VALUES (?)", [address], onDone);
				} else if (onDone)
					onDone();
				if (!bForwarded)
					forwardNewSharedAddressToCosignersOfMyMemberAddresses(address, arrDefinition, assocSignersByPath);
			
			});
		}
	);
```

**File:** wallet_defined_by_addresses.js (L338-375)
```javascript
// Returns a map of signing_path -> address for every ["address", ...] leaf in the definition
function extractAddressPathsFromDefinition(arrDefinition) {
	var result = {};
	function traverse(arr, path) {
		if (!Array.isArray(arr) || arr.length < 2) return;
		var op = arr[0];
		var args = arr[1];
		switch (op) {
			case 'or':
			case 'and':
				if (Array.isArray(args))
					for (var i = 0; i < args.length; i++)
						traverse(args[i], path + '.' + i);
				break;
			case 'r of set':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i], path + '.' + i);
				break;
			case 'weighted and':
				if (args && Array.isArray(args.set))
					for (var i = 0; i < args.set.length; i++)
						traverse(args.set[i].value, path + '.' + i);
				break;
			case 'address':
				result[path] = args;
				break;
			case 'hash':
				result[path] = 'secret';
				break;
			case 'in merkle':
				result[path] = ''; // empty address
				break;
		}
	}
	traverse(arrDefinition, 'r');
	return result;
}
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

**File:** wallet_defined_by_addresses.js (L520-528)
```javascript
function validateAddressDefinition(arrDefinition, handleResult){
	var objFakeUnit = {authors: []};
	var objFakeValidationState = {last_ball_mci: MAX_INT32, bAllowUnresolvedInnerDefinitions: true};
	Definition.validateDefinition(db, arrDefinition, objFakeUnit, objFakeValidationState, null, false, function(err){
		if (err)
			return handleResult(err);
		handleResult();
	});
}
```
