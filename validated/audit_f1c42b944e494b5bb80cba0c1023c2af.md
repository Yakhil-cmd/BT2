### Title
Malicious peer can present a fake "shared address" with an undisclosed unilateral spending branch, tricking the victim into depositing funds that the peer alone can drain - ([File: wallet_defined_by_addresses.js])

### Summary
`handleNewSharedAddress()` in `wallet_defined_by_addresses.js` only checks that the received address definition's hash matches the claimed address and that every `"address"`/`"hash"` leaf in the definition has a matching entry in `body.signers`. It never verifies that the *boolean structure* of the definition actually requires cooperation from the recipient (the victim's own key/address) to spend funds. A definition containing an `"or"`/`"r of set"` branch with a bare `["sig", {pubkey: attacker_pubkey}]` leaf is accepted as a legitimate "shared address" as long as every `"address"`-type leaf has a signer entry - the `"sig"` leaf itself needs no counterpart in `signers` because `extractAddressPathsFromDefinition()` does not record `"sig"` ops at all.

### Finding Description
`extractAddressPathsFromDefinition()` [1](#0-0)  walks the definition tree and records a signing-path→address mapping only for `"address"`, `"hash"`, and `"in merkle"` leaves. It has no case for `"sig"`, so a `["sig", {pubkey}]` leaf anywhere in the tree is silently skipped and never appears in `assocDefinitionAddresses`.

`handleNewSharedAddress()` [2](#0-1)  uses exactly this map to validate `body.signers`: it checks that every entry in `assocDefinitionAddresses` has a corresponding signer, and vice versa, but it applies no check that ensures the definition cannot be satisfied by a single party alone. Because `"sig"` leaves are invisible to this check, an attacker can send a definition such as:

```
["or", [
  ["address", "<victim_real_address>"],
  ["sig", {"pubkey": "<attacker_pubkey>"}]
]]
```

`handleNewSharedAddress` will accept this: the only `"address"` leaf is the victim's, it has a matching signer, and the definition hash matches the claimed shared address. The attacker's `"sig"` leaf requires no acknowledgement. The victim's wallet then stores this as a legitimate `shared_addresses` entry via `addNewSharedAddress()` and shows it (e.g. through `createNewSharedAddress`/contract flows in `arbiter_contract.js`) as jointly protected. On the ledger, however, `Definition.validateAuthentifiers()` in `definition.js` [3](#0-2)  honors the `"or"` semantics: satisfying *either* branch is sufficient to authorize spending. This means the attacker alone, using only their own private key, can produce a valid signed unit spending all funds ever sent to that "shared" address — completely bypassing the victim's participation.

### Impact Explanation
This is a direct analog of the Bitfinex incident's core failure mode (a supposedly multi-party-protected wallet being spendable by an unauthorized single party). Funds sent by an unsuspecting user to a shared/contract address they believe requires joint authorization can be unilaterally and silently drained by the malicious peer who proposed the address, producing concrete unauthorized loss of funds. This satisfies the "concrete unauthorized spending" bar under the Validate rules.

### Likelihood Explanation
The `new_shared_address` message is processed as unprivileged peer-to-peer wallet protocol input (`handleNewSharedAddress` is reachable from any correspondent proposing a shared/contract address, e.g. via prosaic/arbiter contract flows built on `wallet_defined_by_addresses.js`). No special privilege is needed beyond being a device correspondent who can propose a shared-address definition, which is the standard use case for arbiter/prosaic escrow contracts and multi-device wallets. The only requirement is constructing a definition whose only `"address"`-typed leaves are legitimate, while embedding an independent `"sig"` branch — straightforward for any attacker controlling the sending side of the negotiation.

### Recommendation
`extractAddressPathsFromDefinition` (and the validation in `handleNewSharedAddress`) should recursively verify that every leaf capable of independently satisfying the definition (`"sig"`, `"hash"`, `"definition template"`, etc.) is either accounted for as a recognized, expected cosigner, or reject any definition whose top-level boolean structure allows a single un-vetted leaf to satisfy an `"or"`/`"r of set"`/`"weighted and"` branch without corresponding entries in `body.signers`. More generally, the wallet should evaluate the full boolean expression symbolically to confirm that spending genuinely requires cooperation of all expected member addresses before accepting and displaying an address as a "shared"/jointly-controlled address.

### Proof of Concept
1. Attacker (Device B) initiates a shared/contract address flow with victim (Device A), e.g. via the arbiter/prosaic contract wallet flow that calls `createNewSharedAddress`/`handleNewSharedAddress`.
2. Attacker crafts `arrDefinition = ["or", [["address", victim_address], ["sig", {pubkey: attacker_pubkey}]]]` and computes `shared_address = objectHash.getChash160(arrDefinition)`.
3. Attacker sends `new_shared_address` message: `{address: shared_address, definition: arrDefinition, signers: {"r.0": {address: victim_address, device_address: victim_device}}}` (only for the `"address"` leaf — no signer entry required for `"r.1"` because `extractAddressPathsFromDefinition` never records it).
4. Victim's `handleNewSharedAddress` validates: hash matches, `assocDefinitionAddresses = {"r.0": victim_address}` matches `body.signers`, no missing signer for the `"address"` leaf → accepts and stores the shared address, believing it needs both parties.
5. Victim (or a counterparty) sends payment funds to `shared_address` believing it is protected by the victim's own key.
6. Attacker independently constructs a unit spending from `shared_address` using only their own signature on the `"sig"` (`r.1`) branch. `Definition.validateAuthentifiers` accepts it because the `"or"` is satisfied by the `"sig"` branch alone, and the unit is valid and confirmable on the DAG — funds are unilaterally stolen.

### Citations

**File:** wallet_defined_by_addresses.js (L339-375)
```javascript
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

**File:** definition.js (L652-670)
```javascript
			case 'or':
				// ['or', [list of options]]
				var res = false;
				var index = -1;
				async.eachSeries(
					args,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							res = res || arg_res;
							cb3(); // check all members, even if required minimum already found
							//res ? cb3("found") : cb3();
						});
					},
					function(){
						cb2(res);
					}
				);
				break;
```
