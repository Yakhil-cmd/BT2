### Title
Cross-identity binding confusion in `handleNewSharedAddress` allows a paired device to poison co-signer routing and hijack private-payment forwarding - ([File: wallet_defined_by_addresses.js])

### Summary
`wallet_defined_by_addresses.js`'s `handleNewSharedAddress` validates that the shared-address definition hashes to the claimed address, and that each `signers[path].address` matches the address literal embedded in the definition at that path, but it never verifies that the `device_address` claimed for a co-signer is actually controlled by the correspondent that owns that on-chain address. Only the *local* wallet's own addresses have their `device_address` corrected via `determineIfIncludesMeAndRewriteDeviceAddress`; every other signer's `device_address` is trusted verbatim from the attacker-controlled message body and written into `shared_address_signing_paths`. This is structurally the same bug class as CVE-2026-48087: one identity binding (definition chash ↔ claimed address) is checked, but a second, security-critical binding (claimed device/owner identity ↔ real device/owner) is not, letting an attacker splice their own identity into a record that legitimately belongs to someone else.

### Finding Description
`handleNewSharedAddress` (`wallet_defined_by_addresses.js:377-415`) performs these checks on a `new_shared_address` device message body `{address, definition, signers}`:
1. `body.address === objectHash.getChash160(body.definition)` [1](#0-0) 
2. Every `signers[path].address` matches the literal address embedded in `body.definition` at that path via `extractAddressPathsFromDefinition` [2](#0-1) 
3. `determineIfIncludesMeAndRewriteDeviceAddress` only rewrites `device_address` to the local device for signer entries whose `address` is found in the local wallet's own `my_addresses` table; all other entries keep whatever `device_address` the attacker supplied [3](#0-2) 
4. `addNewSharedAddress` writes every signer's `(address, device_address)` pair verbatim into `shared_address_signing_paths` [4](#0-3) 

Crucially, the message is only rejected by the hub/device layer if the sender is not a *known correspondent* at all (device.js's non-correspondent whitelist does not include `new_shared_address`) [5](#0-4) ; there is no check that the sender is one of the addresses actually referenced in the definition, nor that the `device_address` claimed for a third-party member address belongs to that member. On-chain addresses are not secret (they are visible on the public DAG once used), matching the "IDs not strictly secret" caveat in the original report.

An attacker who is merely paired with a victim (correspondent) can craft a shared-address definition that includes: (a) one of the victim's own real addresses (so `determineIfIncludesMeAndRewriteDeviceAddress` succeeds and the "I am a member" check passes at `wallet_defined_by_addresses.js:301-302`), and (b) a second real address belonging to an unrelated third party `C`, but claim `device_address = ATTACKER_DEVICE` for `C`'s signing path. Because only the victim's own address entry gets its `device_address` corrected, the entry for `C` is stored with the attacker's device as the "reachable through" device [6](#0-5) .

This poisoned `shared_address_signing_paths` row is later trusted by `forwardPrivateChainsToOtherMembersOfAddresses`, which joins `shared_address_signing_paths` to `correspondent_devices` purely on `device_address` and forwards private (hidden) payment chains to whatever device is on file [7](#0-6) , and by `sendPrivatePayments`/`forwardPrivateChainsToDevices` in `wallet_general.js` which blindly ships the chain to that device [8](#0-7) . The same table also drives `findAddress`'s signer routing used to solicit signatures (`wallet.js:1233-1316`).

### Impact Explanation
When the victim later composes a payment on the fabricated shared/multisig address involving `C`'s real address, the wallet forwards the associated private divisible/indivisible asset payment chain (containing amounts, blinding factors, and hidden-output proof data) to the attacker's device instead of `C`'s real device. This:
- Leaks confidential private-payment chain data to an unauthorized third party (violates the confidentiality guarantee of "private payment chains" explicitly in scope), and
- Prevents the legitimate owner `C` from ever receiving the chain data needed to spend/prove the private output, effectively freezing/losing access to those private funds since the real recipient never gets the hidden output/blinding information.
Additionally, signature-solicitation routing (`findAddress`) for that fabricated path would be misdirected to the attacker's device, letting the attacker silently withhold cooperation and stall/fail composition of transactions from that shared address (denial of use / freezing of funds tied to the multisig).

No direct on-chain fund theft is possible from this alone, because actual spending still requires a genuine signature validated against the definition's real address (per `validation.js`'s definition-hash checks), so this does not by itself grant unauthorized spending of already-confirmed value — but it is a concrete freezing/leak vector reachable purely by a paired device sending one crafted message.

### Likelihood Explanation
Any device that is already paired (a correspondent) with the victim can trigger this by sending a single `new_shared_address` justsaying message; no special privileges beyond normal pairing are required, and the referenced real addresses (victim's own and the third party's) are publicly observable from the DAG, matching the original report's note that user/address identifiers are "not strictly secret." The victim's wallet processes the message automatically without any user confirmation step visible in `handleNewSharedAddress`.

### Recommendation
In `handleNewSharedAddress`/`determineIfIncludesMeAndRewriteDeviceAddress`, do not trust attacker-supplied `device_address` values for co-signer addresses that are not locally owned. Instead, look up the authoritative device for any address that is already known through existing `shared_address_signing_paths`/`correspondent` records, and reject or require independent confirmation for previously-unknown addresses whose claimed device does not match any existing binding. At minimum, require that private-payment forwarding (`forwardPrivateChainsToOtherMembersOfAddresses`) validate the destination device against an out-of-band or cryptographically-verified association rather than a self-reported field in an inbound message.

### Proof of Concept
1. Attacker device `M` pairs with victim device `V` (normal pairing flow, `device.js:handlePairingMessage`).
2. Attacker observes on-chain address `C_ADDR` belonging to a third-party wallet `C` (public on the DAG) and knows one of `V`'s own addresses `V_ADDR` (also public, e.g. from a prior payment to `M`).
3. Attacker builds `arrDefinition = ["and", [["address", V_ADDR], ["address", C_ADDR]]]`, computes `shared_address = chash(arrDefinition)`.
4. Attacker sends device message: `subject: "new_shared_address", body: {address: shared_address, definition: arrDefinition, signers: {"r.0": {address: V_ADDR, device_address: M}, "r.1": {address: C_ADDR, device_address: M}}}`.
5. `handleNewSharedAddress` on `V` passes all its checks (chash matches, per-path addresses match, `V_ADDR` found in `my_addresses`), `determineIfIncludesMeAndRewriteDeviceAddress` rewrites only `r.0`'s device to `V` itself, leaving `r.1` (`C_ADDR`) bound to `M`.
6. `addNewSharedAddress` inserts `shared_address_signing_paths` rows including `(shared_address, C_ADDR, "r.1", ..., M)`.
7. When `V` later sends a private asset payment to `shared_address`, `forwardPrivateChainsToOtherMembersOfAddresses` forwards the private chain to device `M` (attacker) instead of `C`'s real device, leaking the private payment data and leaving `C` unable to receive/spend the corresponding output.

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

**File:** wallet_defined_by_addresses.js (L383-390)
```javascript
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
```

**File:** wallet_defined_by_addresses.js (L396-405)
```javascript
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
```

**File:** wallet_defined_by_addresses.js (L531-543)
```javascript
function forwardPrivateChainsToOtherMembersOfAddresses(arrChains, arrAddresses, bForwarded, conn, onSaved){
	conn = conn || db;
	conn.query(
		"SELECT device_address FROM shared_address_signing_paths \n\
		JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?) AND device_address!=?", 
		[arrAddresses, device.getMyDeviceAddress()], 
		function(rows){
			console.log("shared address devices: "+rows.length);
			var arrDeviceAddresses = rows.map(function(row){ return row.device_address; });
			walletGeneral.forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, bForwarded, conn, onSaved);
		}
	);
}
```

**File:** device.js (L213-220)
```javascript
				else{ // correspondent not known
					var arrSubjectsAllowedFromNoncorrespondents = ["pairing", "my_xpubkey", "wallet_fully_approved"];
					if (arrSubjectsAllowedFromNoncorrespondents.indexOf(json.subject) === -1){
						respondWithError("correspondent not known and not whitelisted subject");
						return;
					}
					handleMessage(false);
				}
```

**File:** wallet_general.js (L19-40)
```javascript
function sendPrivatePayments(device_address, arrChains, bForwarded, conn, onSaved){
	var body = {chains: arrChains};
	if (bForwarded)
		body.forwarded = true;
	device.sendMessageToDevice(device_address, "private_payments", body, {
		ifOk: function(){},
		ifError: function(){},
		onSaved: onSaved
	}, conn);
}

function forwardPrivateChainsToDevices(arrDeviceAddresses, arrChains, bForwarded, conn, onSaved){
	console.log("devices: "+arrDeviceAddresses);
	async.eachSeries(
		arrDeviceAddresses,
		function(device_address, cb){
			console.log("forwarding to device "+device_address);
			sendPrivatePayments(device_address, arrChains, bForwarded, conn, cb);
		},
		onSaved
	);
}
```
