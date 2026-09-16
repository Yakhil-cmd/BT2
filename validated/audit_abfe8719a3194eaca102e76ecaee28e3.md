Confirmed: `address_definition_change` lets an address holder swap in a new definition (e.g. removing a cosigner from a shared/multisig address) without any corresponding update to `shared_address_signing_paths`, which is the table used to decide who still receives forwarded private-payment data for that address.

### Title
Removed cosigner of a shared/multisig address continues to receive private payment data after key rotation - (File: wallet_defined_by_addresses.js)

### Summary
When a multi-member (shared) address rotates its definition via an `address_definition_change` message (e.g. to remove a cosigner or replace one signer's key), the wallet layer never updates the `shared_address_signing_paths` table that records which devices/addresses are members of a shared address. All logic that decides who is allowed to see private payment chains for that address (`forwardPrivateChainsToOtherMembersOfAddresses`, `readAllControlAddresses`, `forwardPrivateChainsToOtherMembersOfSharedAddresses`) keys off this stale table rather than the address's currently active definition, so a removed cosigner keeps receiving forwarded private (whisper-equivalent) payment content indefinitely.

### Finding Description
Shared/multisig addresses are created once, and their cosigner membership is recorded permanently in `shared_address_signing_paths` at creation time (`addNewSharedAddress`) [1](#0-0) . Ocore explicitly supports changing an address's active definition later, independent of the address itself, through the `address_definition_change` message — the chash of the address stays fixed but a brand-new definition (which may drop or replace a cosigner) becomes authoritative going forward [2](#0-1) [3](#0-2) . Actual signature/authorization validation correctly consults the latest definition for the address via `storage.readDefinitionByAddress(conn, address, last_ball_mci, ...)` [4](#0-3) [5](#0-4) , so on-chain spending authority is correctly revoked for a removed cosigner.

However, the private-payment visibility layer does not consult this current definition at all. `readAllControlAddresses` and `forwardPrivateChainsToOtherMembersOfAddresses` simply select every `device_address` ever recorded in `shared_address_signing_paths` for the shared address [6](#0-5) , and `forwardPrivateChainsToOtherMembersOfSharedAddresses` in `wallet.js` uses the same stale table to decide which devices to forward private chains to [7](#0-6) . There is no code path anywhere in the codebase that deletes or updates rows in `shared_address_signing_paths` in response to an `address_definition_change`; a full repo search for `DELETE FROM shared_address_signing_paths` / `UPDATE shared_address_signing_paths` found no matches. As a result, the private-payment forwarding mechanism behaves like the Discourse whisper bug: a party that was legitimately privy to the address's private financial data at creation time continues to be treated as an authorized recipient of new private payment chains for that address even after the address's definition has been changed to exclude them, because the visibility check relies on stale membership state instead of the live authorization set.

### Impact Explanation
This causes ongoing loss of confidentiality of private, cosigned financial payments after a party is deliberately removed from a shared/multisig address (a routine operation, e.g. rotating a compromised or ex-partner's key). A removed cosigner's device keeps being sent full private-payment chain content (amounts, addresses, blinding factors) for every future spend from/through that shared address, which is exactly the class of unauthorized-visibility-of-private-data harm called out by the analog report (users retaining visibility of privileged content after their access should have been revoked). Because the forwarding is automatic and silent (no confirmation, no re-check of authorization), an ex-cosigner has continuous access to counterparties' private transaction data indefinitely, undermining the confidentiality guarantees relied upon by any private/indivisible-asset payment or shared-address financial arrangement in the wallet.

### Likelihood Explanation
Rotating an address's definition (removing/replacing a cosigner) is a normal, user-reachable operation supported by the `address_definition_change` message type, and shared multisig addresses backed by `shared_address_signing_paths` are commonly used for private asset payments (indivisible/divisible private assets forward chains specifically through this address type — see `forwardPrivateChainsToOtherMembersOfAddresses` invocation sites). No special network position or malicious peer is needed; any legitimate wallet owner performing key rotation on a shared address triggers this stale-authorization condition automatically for all subsequent private payments to/through that address.

### Recommendation
Before forwarding private payment chains to devices retrieved from `shared_address_signing_paths`, cross-check the address's currently active definition (via `storage.readDefinitionByAddress`) and filter out any signing paths/devices that are no longer part of the live definition. Additionally, on processing/persisting an `address_definition_change` for a shared address, proactively prune or mark stale rows in `shared_address_signing_paths` (and the child `shared_addresses`/related caches) so the "who can see private data for this address" state remains in sync with "who can currently sign for this address."

### Proof of Concept
1. Two devices A and B jointly create a shared address `S` with definition `["and", [["address","A"], ["address","B"]]]`, populating `shared_address_signing_paths` for both device addresses (`addNewSharedAddress`).
2. The owner of `S` later posts an `address_definition_change` message that redefines `S`'s active definition to no longer reference B's address (e.g., rotates to a new sole-signer key), which is accepted by validation since `address_definition_change` only requires the new `definition_chash` to be well-formed and the sender to be an author of the original address.
3. A new private payment is subsequently sent to/through `S`. `forwardPrivateChainsToOtherMembersOfSharedAddresses` / `forwardPrivateChainsToOtherMembersOfAddresses` still queries `shared_address_signing_paths WHERE shared_address = S`, which still contains B's device row, and forwards the full private payment chain to B.
4. B, despite no longer being part of `S`'s active definition and having no ability to co-sign, still receives and can decrypt the private payment content — analogous to a removed Discourse group member continuing to see whispers.

### Citations

**File:** wallet_defined_by_addresses.js (L239-268)
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
}
```

**File:** wallet_defined_by_addresses.js (L531-561)
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

**File:** validation.js (L1188-1208)
```javascript
		}
		// we check signatures using the latest address definition before last ball
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){
				storage.readAADefinition(conn, objAuthor.address, objValidationState.last_ball_mci, function (arrAADefinition) {
					if (arrAADefinition)
						return callback(createTransientError("will not validate unit signed by AA"));
					if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci)
						return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " not found before last ball");
					findUnstableInitialDefinition(definition_chash, function (arrDefinition) {
						if (!arrDefinition)
							return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " is not defined");
						bInitialDefinition = true;
						validateAuthentifiers(arrDefinition);
					});
				});
			},
			ifFound: function(arrAddressDefinition){
				validateAuthentifiers(arrAddressDefinition);
			}
		});
```

**File:** validation.js (L1469-1483)
```javascript
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){ // first use of the definition_chash (in particular, of the address, when definition_chash=address)
				try {
					if (objectHash.getChash160(arrAddressDefinition) !== definition_chash)
						return callback("wrong definition: " + objectHash.getChash160(arrAddressDefinition) + "!==" + definition_chash);
				}
				catch (e) {
					return callback("definition hash failed: " + e.toString());
				}
				callback();
			},
			ifFound: function(arrAddressDefinition2){ // arrAddressDefinition2 can be different
				handleDuplicateAddressDefinition(arrAddressDefinition2);
			}
		});
```

**File:** validation.js (L1719-1745)
```javascript
		case "address_definition_change":
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["definition_chash", "address"]))
				return callback("unknown fields in address_definition_change");
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			var address;
			if (objUnit.authors.length > 1){
				if (!isValidAddress(payload.address))
					return callback("when multi-authored, must indicate address");
				if (arrAuthorAddresses.indexOf(payload.address) === -1)
					return callback("foreign address");
				address = payload.address;
			}
			else{
				if ('address' in payload)
					return callback("when single-authored, must not indicate address");
				address = arrAuthorAddresses[0];
			}
			if (!objValidationState.arrDefinitionChangeFlags)
				objValidationState.arrDefinitionChangeFlags = {};
			if (objValidationState.arrDefinitionChangeFlags[address])
				return callback("can be only one definition change per address");
			objValidationState.arrDefinitionChangeFlags[address] = true;
			if (!isValidAddress(payload.definition_chash))
				return callback("bad new definition_chash");
			return callback();
```

**File:** writer.js (L184-192)
```javascript
				if (message.payload_location === "inline"){
					switch (message.app){
						case "address_definition_change":
							var definition_chash = message.payload.definition_chash;
							var address = message.payload.address || objUnit.authors[0].address;
							conn.addQuery(arrQueries, 
								"INSERT INTO address_definition_changes (unit, message_index, address, definition_chash) VALUES(?,?,?,?)", 
								[objUnit.unit, i, address, definition_chash]);
							break;
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
