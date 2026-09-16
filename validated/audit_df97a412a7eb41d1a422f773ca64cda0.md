### Title
Insufficient verification of signing-path ownership when accepting a peer-supplied `new_shared_address` message allows a paired device to hijack routing of a co-signer's own address — [File: wallet_defined_by_addresses.js]

### Summary
The Mattermost CVE (BIT-mattermost-2024-2450) is rooted in failing to verify true ownership of an identity when a security-relevant binding (auth method) is switched, letting an attacker splice themselves into another user's account. The structural analog in `ocore` is `handleNewSharedAddress()` / `determineIfIncludesMeAndRewriteDeviceAddress()` in `wallet_defined_by_addresses.js`, where a paired correspondent device fully controls the `signers` map (`address -> device_address` bindings) of a new multisig/shared address, and the local wallet only "corrects" (rewrites) the device-address binding for its own address when it does not already see its own device address mentioned anywhere in the message — otherwise it blindly trusts the attacker-supplied bindings, including the mapping for the victim's *own* address.

### Finding Description
`handleNewSharedAddress(body, callbacks)` [1](#0-0)  accepts an unauthenticated (beyond device-pairing) claim from a correspondent describing a new shared/multisig address: `body.definition` (an oscript address definition) and `body.signers` (a map from signing path to `{address, device_address}`). It validates that:
- the definition hashes to `body.address` (structural integrity only),
- each `signers[path].address` matches the `address` leaf found at that path in the definition (`extractAddressPathsFromDefinition`),
- every address-leaf path has a corresponding signer entry.

None of these checks verify which **device** is actually authorized to sign for a given member address — that binding is taken purely from the attacker-supplied `signers[path].device_address`.

Ownership correction happens only in `determineIfIncludesMeAndRewriteDeviceAddress()` [2](#0-1) :
```
var bHasMyDeviceAddress = false;
for (var signing_path in assocSignersByPath){
    var signerInfo = assocSignersByPath[signing_path];
    if (signerInfo.device_address === device.getMyDeviceAddress())
        bHasMyDeviceAddress = true;
    ...
}
...
if (!bHasMyDeviceAddress){
    for (var signing_path in assocSignersByPath){
        var signerInfo = assocSignersByPath[signing_path];
        if (signerInfo.address && arrMyMemberAddresses.indexOf(signerInfo.address) >= 0)
            signerInfo.device_address = device.getMyDeviceAddress();
    }
}
```
`bHasMyDeviceAddress` is set to `true` as soon as *any* entry in the attacker-controlled `signers` map claims `device_address === device.getMyDeviceAddress()` — regardless of which signing path or address that entry refers to. Because the sending peer knows the victim's device address (it is a paired correspondent, and device addresses are routinely exchanged during pairing/shared-address setup), it can trivially satisfy this flag by attaching the victim's device address to an unrelated/decoy path, while for the path that actually corresponds to the victim's real own address it substitutes the attacker's own `device_address`.

Since `bHasMyDeviceAddress` is now `true`, the self-correction loop is skipped entirely, so the victim's *own* address gets recorded in `shared_address_signing_paths` (`addNewSharedAddress`, called next: [3](#0-2) ) with `device_address` pointing to the attacker instead of the victim.

### Impact Explanation
`shared_address_signing_paths.device_address` is the routing table the wallet code uses to know which device to ask for a co-signer's signature when constructing a payment from the shared/multisig address (used throughout `wallet.js` and referenced by balance/spend logic — 17 references in `wallet.js`, 4 in `balances.js`). By poisoning this table so the victim's own address is bound to the attacker's device, the victim's wallet will send future signing requests for that shared address to the attacker instead of to the victim's own device (or to the victim's real cosigner device), and the attacker cannot produce a valid signature (they don't hold the private key), permanently stalling any payment attempt that needs that signing path. This yields **AA/wallet fund freezing** on that shared address: it becomes practically unspendable through the normal flow, satisfying the "fund loss or freezing" impact criterion. It also corrupts local consensus-adjacent bookkeeping about who legitimately controls a shared address, which is the same class of "ownership binding is not properly verified/re-verified when third-party claims are accepted" as the referenced CVE.

### Likelihood Explanation
The `new_shared_address` device message is reachable from any already-paired correspondent device without further authorization (`wallet.js` `case "new_shared_address": walletDefinedByAddresses.handleNewSharedAddress(...)` [4](#0-3) ), i.e. exactly the class of "paired device" actor explicitly in scope. No special privilege beyond an existing device pairing (a normal, common state between wallet users setting up a shared address) is required, and the attacker needs only to know the victim's device address, which the protocol itself routinely discloses during any prior shared-address negotiation or pairing exchange. This makes exploitation straightforward once two devices are paired and any shared-address relationship is being established.

### Recommendation
In `determineIfIncludesMeAndRewriteDeviceAddress`, do not rely on the presence of *any* attacker-supplied entry claiming `device_address === my device address` to skip correction. Instead, always force `device_address = device.getMyDeviceAddress()` for every `signers[path]` whose `address` is found in `my_addresses` (or in `shared_addresses` under my control), unconditionally, regardless of `bHasMyDeviceAddress`. More generally, the local wallet should never trust an externally supplied device-address binding for an address it recognizes as its own or as one of its member/shared addresses.

### Proof of Concept
1. Devices V (victim) and A (attacker) are paired correspondents (a normal prerequisite for any shared address setup).
2. A crafts an oscript definition `D` for a 2-of-2 (or N-of-N) address referencing V's real address `addrV` at path `r.0` and some other address `addrX` (owned or fabricated by A) at path `r.1`.
3. A sends a `new_shared_address` device message to V with:
   ```
   body = {
     address: chash160(D),
     definition: D,
     signers: {
       "r.0": { address: addrV, device_address: A_device_address },   // victim's real address mis-bound to attacker
       "r.1": { address: addrX, device_address: V_device_address }    // decoy entry that falsely flags "I see V's device"
     }
   }
   ```
4. On V's node, `handleNewSharedAddress` passes structural checks (definition hash matches, path/address correspondence matches). `determineIfIncludesMeAndRewriteDeviceAddress` sets `bHasMyDeviceAddress = true` because of the decoy `"r.1"` entry, so the correction loop that would fix `"r.0"`'s device_address back to V is skipped.
5. `addNewSharedAddress` persists `shared_address_signing_paths` with `addrV` bound to A's device address.
6. When V later attempts to spend from the shared address, the wallet software routes the co-signing request for `addrV`'s path to A's device instead of V's own device, and the payment can never be completed through the normal flow — the shared address funds are effectively frozen.

Note: I was not able to fully trace, within the available tool budget, the exact downstream code path in `wallet.js`/`composer.js` that consumes `shared_address_signing_paths.device_address` when assembling signing requests for a spend from a shared address; confirming the precise mechanics of the freeze (versus a UI/local-only inconvenience) would benefit from a full Devin session with direct file access to `wallet.js`'s multisig-signing-request flow and `composer.js`'s use of `readSharedAddressCosigners`/`readFullSigningPaths`.

### Citations

**File:** wallet_defined_by_addresses.js (L239-252)
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
```

**File:** wallet_defined_by_addresses.js (L281-315)
```javascript
function determineIfIncludesMeAndRewriteDeviceAddress(assocSignersByPath, handleResult){
	var assocMemberAddresses = {};
	var bHasMyDeviceAddress = false;
	for (var signing_path in assocSignersByPath){
		var signerInfo = assocSignersByPath[signing_path];
		if (signerInfo.device_address === device.getMyDeviceAddress())
			bHasMyDeviceAddress = true;
		if (signerInfo.address)
			assocMemberAddresses[signerInfo.address] = true;
	}
	var arrMemberAddresses = Object.keys(assocMemberAddresses);
	if (arrMemberAddresses.length === 0)
		return handleResult("no member addresses?");
	db.query(
		"SELECT address, 'my' AS type FROM my_addresses WHERE address IN(?) \n\
		UNION \n\
		SELECT shared_address AS address, 'shared' AS type FROM shared_addresses WHERE shared_address IN(?)", 
		[arrMemberAddresses, arrMemberAddresses],
		function(rows){
		//	handleResult(rows.length === arrMyMemberAddresses.length ? null : "Some of my member addresses not found");
			if (rows.length === 0)
				return handleResult("I am not a member of this shared address");
			var arrMyMemberAddresses = rows.filter(function(row){ return (row.type === 'my'); }).map(function(row){ return row.address; });
			// rewrite device address for my addresses
			if (!bHasMyDeviceAddress){
				for (var signing_path in assocSignersByPath){
					var signerInfo = assocSignersByPath[signing_path];
					if (signerInfo.address && arrMyMemberAddresses.indexOf(signerInfo.address) >= 0)
						signerInfo.device_address = device.getMyDeviceAddress();
				}
			}
			handleResult();
		}
	);
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

**File:** wallet.js (L236-245)
```javascript
			case "new_shared_address":
				// {address: "BASE32", definition: [...], signers: {...}}
				walletDefinedByAddresses.handleNewSharedAddress(body, {
					ifError: callbacks.ifError,
					ifOk: function(){
						callbacks.ifOk();
						eventBus.emit('maybe_new_transactions');
					}
				});
				break;
```
