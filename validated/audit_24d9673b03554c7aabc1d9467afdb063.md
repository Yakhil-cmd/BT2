## Finding [1](#0-0) An `or`/`and`/`r of set` shared-address definition is flattened by `extractAddressPathsFromDefinition` into one row per leaf `["address", ...]` in `shared_address_signing_paths`, with no indication of which branches are mutually exclusive alternatives. [2](#0-1) [3](#0-2) When a private payment chain is received, `forwardPrivateChainsToOtherMembersOfOutputAddresses`/`forwardPrivateChainsToOtherMembersOfAddresses`/`readAllControlAddresses` look up **every** `device_address` ever recorded as a signing path for the shared address (recursively, through nested shared/multisig addresses) and push the full private payment chain (amounts, blinding, addresses) to all of them, without checking whether that particular device's branch of the boolean definition was actually required to authorize this specific spend. [4](#0-3) [5](#0-4) 

### Title
Private payment data disclosed to non-participating "or"-branch cosigners of a shared address - (File: wallet_defined_by_addresses.js)

### Summary
For a shared address whose definition is `["or", [addrA, addrB]]` (or any structure with alternative, mutually exclusive signer sets), ocore treats *every* leaf address/device recorded in `shared_address_signing_paths` as an entitled recipient of private-payment forwarding, regardless of whether that device's key path was actually part of the signature that authorized the transaction.

### Finding Description
`extractAddressPathsFromDefinition` (used by `handleNewSharedAddress`) walks the entire definition tree — `or`, `and`, `r of set`, `weighted and` — and records a signing path for every leaf `["address", ...]`, with the resulting `shared_address_signing_paths` table storing one row per leaf member and its `device_address`, with no field capturing which OR-branch a member belongs to. [1](#0-0) [6](#0-5) 

When a private payment is sent to (or from) such a shared address, `forwardPrivateChainsToOtherMembersOfOutputAddresses` calls `walletDefinedByAddresses.forwardPrivateChainsToOtherMembersOfAddresses`, which simply selects **all** `device_address` rows from `shared_address_signing_paths` for the shared address (excluding only my own device) and forwards the full private chain (asset, amounts, blinding factors, output addresses) to every one of them:
```js
conn.query(
  "SELECT device_address FROM shared_address_signing_paths \n\
  JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?) AND device_address!=?",
  [arrAddresses, device.getMyDeviceAddress()],
  ...
);
``` [2](#0-1) 

Similarly, `forwardPrivateChainsToOtherMembersOfSharedAddresses` uses `readAllControlAddresses`, which recursively expands to *all* control addresses/devices nested anywhere in the definition tree of the paying address, again with no filtering by which OR-branch actually signed: [3](#0-2) [5](#0-4) 

This is directly analogous to CVE-2021-44886: a "substitute" (here, the alternative/OR-branch cosigner) is granted the same information stream (ticket/payment notifications) as the primary party, without verifying that the substitute actually holds equivalent authorization/participation for that specific event. In ocore's case, an attacker who is one alternative signer on a 2-of-2 "or" shared address (e.g. an escrow/arbiter-style address created via `arbiter_contract.js`'s `deriveSharedAddress`, or any user-composed `or` definition) automatically receives the full plaintext of private payments authorized solely by the other, unrelated branch.

### Impact Explanation
Any unprivileged party who is included as an alternative (`or`) signer on a shared address — a role reachable simply by being invited into a multi-party address definition, e.g. via `create_new_shared_address`/`new_shared_address` device messages — receives private payment details (amounts, addresses, blinding factors) for transactions that were authorized entirely by the *other* branch and that they had no legitimate need to see. This breaks the confidentiality guarantee of private/indivisible assets and of privacy-sensitive multi-party contracts (arbiter/prosaic contracts), which rely on the fact that only actual transaction participants see the plaintext payload.

### Likelihood Explanation
No special privilege is needed: an attacker only needs to be added as a co-signer/member on any branch of an `or` (or similar alternative) shared-address definition — a normal, low-friction wallet operation — and then wait for the other member(s) to make private payments through that address. The disclosure happens automatically via existing forwarding logic (`forwardPrivateChainsToOtherMembersOfOutputAddresses`, `forwardPrivateChainsToOtherMembersOfSharedAddresses`), with no additional action required from the attacker.

### Recommendation
Track, per signing path, which specific unit_authors/inputs actually exercised that path when a spend occurs, and only forward private chains to devices whose signing path was part of the definition branch actually satisfied by the unit's authors — not to every device ever recorded in `shared_address_signing_paths` for the address. Alternatively, when building `shared_address_signing_paths`, record the OR-branch grouping so forwarding logic can exclude devices belonging to branches that were not used to authorize the specific unit.

### Proof of Concept
1. Device A and Device B jointly create a shared address with definition `["or", [["address", A], ["address", B]]]` via `create_new_shared_address` / `approve_new_shared_address` / `new_shared_address` messages, resulting in both A and B recorded in `shared_address_signing_paths` for the address.
2. A third-party counterparty sends a private (divisible/indivisible) asset payment to this shared address, authorized only by Device A's key (satisfying the `or` branch containing A alone).
3. Device A receives and validates the private chain, then calls `forwardPrivateChainsToOtherMembersOfOutputAddresses` → `forwardPrivateChainsToOtherMembersOfAddresses`, which queries all `device_address`es on `shared_address_signing_paths` for the shared address and forwards the full private payload — including amount and blinding — to Device B, even though B's key was never used and B has no legitimate need to know the transaction details.

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

**File:** wallet_defined_by_addresses.js (L545-561)
```javascript
function readAllControlAddresses(conn, arrAddresses, handleLists){
	conn = conn || db;
	conn.query(
		"SELECT DISTINCT address, shared_address_signing_paths.device_address, (correspondent_devices.device_address IS NOT NULL) AS have_correspondent \n\
		FROM shared_address_signing_paths LEFT JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?)", 
		[arrAddresses], 
		function(rows){
			if (rows.length === 0)
				return handleLists([], []);
			var arrControlAddresses = rows.map(function(row){ return row.address; });
			var arrControlDeviceAddresses = rows.filter(function(row){ return row.have_correspondent; }).map(function(row){ return row.device_address; });
			readAllControlAddresses(conn, arrControlAddresses, function(arrControlAddresses2, arrControlDeviceAddresses2){
				handleLists(_.union(arrControlAddresses, arrControlAddresses2), _.union(arrControlDeviceAddresses, arrControlDeviceAddresses2));
			});
		}
	);
}
```

**File:** wallet.js (L1082-1116)
```javascript
function forwardPrivateChainsToOtherMembersOfOutputAddresses(arrChains, bForwarded, conn, onSaved){
	console.log("forwardPrivateChainsToOtherMembersOfOutputAddresses", arrChains);
	var assocOutputAddresses = {};
	arrChains.forEach(function(arrPrivateElements){
		var objHeadPrivateElement = arrPrivateElements[0];
		var payload = objHeadPrivateElement.payload;
		payload.outputs.forEach(function(output){
			if (output.address)
				assocOutputAddresses[output.address] = true;
		});
		if (objHeadPrivateElement.output && objHeadPrivateElement.output.address)
			assocOutputAddresses[objHeadPrivateElement.output.address] = true;
	});
	var arrOutputAddresses = Object.keys(assocOutputAddresses);
	console.log("output addresses", arrOutputAddresses);
	conn = conn || db;
	if (!onSaved)
		onSaved = function(){};
	readWalletsByAddresses(conn, arrOutputAddresses, function(arrWallets){
		if (arrWallets.length === 0){
		//	breadcrumbs.add("forwardPrivateChainsToOtherMembersOfOutputAddresses: " + JSON.stringify(arrChains)); // remove in livenet
		//	eventBus.emit('nonfatal_error', "not my wallet? output addresses: "+arrOutputAddresses.join(', '), new Error());
		//	throw Error("not my wallet? output addresses: "+arrOutputAddresses.join(', '));
		}
		var arrFuncs = [];
		if (arrWallets.length > 0)
			arrFuncs.push(function(cb){
				walletDefinedByKeys.forwardPrivateChainsToOtherMembersOfWallets(arrChains, arrWallets, bForwarded, conn, cb);
			});
		arrFuncs.push(function(cb){
			walletDefinedByAddresses.forwardPrivateChainsToOtherMembersOfAddresses(arrChains, arrOutputAddresses, bForwarded, conn, cb);
		});
		async.series(arrFuncs, onSaved);
	});
}
```

**File:** wallet.js (L2520-2533)
```javascript
function forwardPrivateChainsToOtherMembersOfSharedAddresses(arrChainsOfCosignerPrivateElements, arrPayingAddresses, excluded_device_address, bForwarded, conn, onDone){
	walletDefinedByAddresses.readAllControlAddresses(conn, arrPayingAddresses, function(arrControlAddresses, arrControlDeviceAddresses){
		arrControlDeviceAddresses = arrControlDeviceAddresses.filter(function(device_address) {
			return (device_address !== device.getMyDeviceAddress() && device_address !== excluded_device_address);
		});
		walletDefinedByKeys.readDeviceAddressesControllingPaymentAddresses(conn, arrControlAddresses, function(arrMultisigDeviceAddresses){
			arrMultisigDeviceAddresses = _.difference(arrMultisigDeviceAddresses, arrControlDeviceAddresses);
			// counterparties on shared addresses must forward further, that's why bForwarded=false
			walletGeneral.forwardPrivateChainsToDevices(arrControlDeviceAddresses, arrChainsOfCosignerPrivateElements, bForwarded, conn, function(){
				walletGeneral.forwardPrivateChainsToDevices(arrMultisigDeviceAddresses, arrChainsOfCosignerPrivateElements, true, conn, onDone);
			});
		});
	});
}
```
