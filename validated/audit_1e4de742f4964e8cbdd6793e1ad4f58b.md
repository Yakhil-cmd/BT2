## Analysis

I found a directly analogous vulnerability in `ocore`. The Astaria bug is a public/unauthenticated state-deletion function (`_deleteLienPosition`) that erases critical multi-party debt-tracking data with no ownership check. The closest reachable analog in `ocore` is the `reject_new_shared_address` device-message handler, which deletes pending shared-(multisig)-address coordination data for *any* `definition_template_chash` supplied by a paired device, without verifying that the sender is actually one of the parties (cosigners) involved in that particular pending shared address. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Unauthorized Deletion of Pending Shared-Address Coordination Data via `reject_new_shared_address` - (File: wallet.js)

### Summary
The device-message handler for the `reject_new_shared_address` subject deletes a pending shared (multisig) address's records purely based on the attacker-supplied `address_definition_template_chash`, without validating that the sending device is actually a member/cosigner referenced in `pending_shared_address_signing_paths` for that chash.

### Finding Description
When a device wants to decline participation in the creation of a shared (multisig) address, it sends a `reject_new_shared_address` message. The handler in `wallet.js` only validates that `address_definition_template_chash` looks like a valid address/hash, then immediately calls `walletDefinedByAddresses.deletePendingSharedAddress()`:

```js
case "reject_new_shared_address":
    // {address_definition_template_chash: "BASE32"}
    if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
        return callbacks.ifError("invalid addr def c-hash");
    walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash);
    callbacks.ifOk();
    break;
``` [1](#0-0) 

`deletePendingSharedAddress` deletes rows from `pending_shared_address_signing_paths` and `pending_shared_addresses` matching only the chash — with no `device_address` (sender) filter at all:

```js
// unused
function deletePendingSharedAddress(address_definition_template_chash){
	db.query("DELETE FROM pending_shared_address_signing_paths WHERE definition_template_chash=?", [address_definition_template_chash], function(){
		db.query("DELETE FROM pending_shared_addresses WHERE definition_template_chash=?", [address_definition_template_chash], function(){});
	});
}
``` [2](#0-1) 

Contrast this with `approvePendingSharedAddress`, the sibling function for the "approve" path, which correctly scopes its `UPDATE` with `AND device_address=?` so a device can only affect its own row:

```js
"UPDATE pending_shared_address_signing_paths SET address=?, device_addresses_by_relative_signing_paths=?, approval_date="+db.getNow()+" \n\
WHERE definition_template_chash=? AND device_address=?",
[address, JSON.stringify(assocDeviceAddressesByRelativeSigningPaths), address_definition_template_chash, from_address],
``` [4](#0-3) 

The "reject" path has no equivalent scoping — `from_address` (the actual message sender, derived from the verified device-message signature) is never passed to or checked in `deletePendingSharedAddress`. Any device that is already a paired correspondent (a low bar — pairing is done via widely shareable pairing codes/QR links used by wallets, bots, exchanges, escrow/arbiter services, etc.) can invalidate the shared-address setup process of two or more *unrelated* devices simply by supplying their `definition_template_chash`.

Reaching this code requires only being a "paired device" sending a `hub/message`; `reject_new_shared_address` is not in the `arrSubjectsAllowedFromNoncorrespondents` whitelist, but pairing itself is trivial/one-directional and commonly automated (e.g., bots, service wallets), so this attacker class is realistic and within scope. [5](#0-4) [6](#0-5) 

### Impact Explanation
Shared addresses in `ocore` back multisig wallets, escrow, arbiter contracts, and similar constructs. The `pending_shared_addresses` / `pending_shared_address_signing_paths` tables track collected approvals as parties sign on. Because `approvePendingSharedAddress` records `approval_date` and refuses to let a device "change its mind" once approved, deletion of these records destroys the approval work already done by legitimate cosigners:

```js
if (rows[0].approval_date) // you've already approved this wallet, you can't change your mind
    return onDone();
```
(analogous protection exists in the sibling `wallet_defined_by_keys.js:deleteWallet`, but is entirely absent for shared addresses) [7](#0-6) 

An attacker with knowledge of a target `definition_template_chash` (e.g., a semi-trusted bot/service that is paired with many users, or one of the legitimate cosigners acting maliciously against another cosigner mid-process) can repeatedly wipe pending shared-address negotiation state for third parties, permanently preventing completion of the intended multisig/escrow/arbiter address — a denial-of-service on a core wallet-coordination primitive that can strand funds if counterparties already began off-chain or on-chain coordination expecting the shared address to materialize (e.g. arbiter-contract flows that build directly on top of shared addresses).

### Likelihood Explanation
The handler is reachable by any already-paired device without further authorization checks and requires only knowledge of the `address_definition_template_chash` (obtainable e.g. by a cosigner participating in — but not authorized to unilaterally cancel — the negotiation, or a rogue/compromised bot service paired with the victim). No special privileges beyond a valid device pairing are needed, which is routinely established via public pairing codes for wallet/bot services, making this a "paired device" reachable, low-effort vector.

### Recommendation
Scope the deletion to the sender exactly as `approvePendingSharedAddress` does, e.g. require the caller to prove device_address membership before allowing rejection/deletion:
```js
db.query("SELECT 1 FROM pending_shared_address_signing_paths WHERE definition_template_chash=? AND device_address=?",
  [address_definition_template_chash, from_address], function(rows){
    if (rows.length === 0)
      return callbacks.ifError("not a member of this pending shared address");
    walletDefinedByAddresses.deletePendingSharedAddress(address_definition_template_chash);
    callbacks.ifOk();
});
```
Alternatively, change `deletePendingSharedAddress` to only remove the calling device's own row (mirroring "reject" semantics for a single cosigner) and only purge the whole pending address once all remaining rows are gone or all have explicitly rejected.

### Proof of Concept
1. Device A and Device B (and possibly more) begin creating a shared address; a `pending_shared_addresses`/`pending_shared_address_signing_paths` entry keyed by `address_definition_template_chash = X` is created and A approves via `approve_new_shared_address` (setting `approval_date`).
2. An unrelated but paired Device M (e.g., a bot/service both A and B are paired with, or a malicious observer who learned `X`) sends a `hub/message` with `subject: "reject_new_shared_address", body: { address_definition_template_chash: X }`.
3. `wallet.js`'s handler validates only the format of `X` and calls `deletePendingSharedAddress(X)`, deleting both `pending_shared_addresses` and all `pending_shared_address_signing_paths` rows for `X` — including A's already-recorded approval — without ever checking that Device M was one of the intended cosigners.
4. The shared-address creation permanently fails for A and B; A's completed approval work is lost, and the flow (e.g., an arbiter/escrow multisig setup) must restart, with no involvement or consent required from either legitimate party.

### Citations

**File:** wallet.js (L150-160)
```javascript
			case "create_new_wallet":
				// {wallet: "base64", wallet_definition_template: [...]}
				walletDefinedByKeys.handleOfferToCreateNewWallet(body, from_address, callbacks);
				break;
			
			case "cancel_new_wallet":
				// {wallet: "base64"}
				if (!ValidationUtils.isNonemptyString(body.wallet))
					return callbacks.ifError("no wallet");
				walletDefinedByKeys.deleteWallet(body.wallet, from_address, callbacks.ifOk);
				break;
```

**File:** wallet.js (L228-234)
```javascript
			case "reject_new_shared_address":
				// {address_definition_template_chash: "BASE32"}
				if (!ValidationUtils.isValidAddress(body.address_definition_template_chash))
					return callbacks.ifError("invalid addr def c-hash");
				walletDefinedByAddresses.deletePendingSharedAddress(body.address_definition_template_chash);
				callbacks.ifOk();
				break;
```

**File:** wallet_defined_by_addresses.js (L103-146)
```javascript
// called from UI (unused)
// my address is not filled explicitly, it is specified as variable in the template like external addresses
// assocMyDeviceAddressesByRelativeSigningPaths points to my device addresses that hold the actual signing keys
function createNewSharedAddressByTemplate(arrAddressDefinitionTemplate, my_address, assocMyDeviceAddressesByRelativeSigningPaths){
	validateAddressDefinitionTemplate(arrAddressDefinitionTemplate, device.getMyDeviceAddress(), function(err, assocMemberDeviceAddressesBySigningPaths){
		if(err) {
			throw Error(err);
		}

		// assocMemberDeviceAddressesBySigningPaths are keyed by paths from root to member addresses (not all the way to signing keys)
		var arrMemberSigningPaths = Object.keys(assocMemberDeviceAddressesBySigningPaths);
		var address_definition_template_chash = objectHash.getChash160(arrAddressDefinitionTemplate);
		db.query(
			"INSERT INTO pending_shared_addresses (definition_template_chash, definition_template) VALUES(?,?)", 
			[address_definition_template_chash, JSON.stringify(arrAddressDefinitionTemplate)],
			function(){
				async.eachSeries(
					arrMemberSigningPaths, 
					function(signing_path, cb){
						var device_address = assocMemberDeviceAddressesBySigningPaths[signing_path];
						var fields = "definition_template_chash, device_address, signing_path";
						var values = "?,?,?";
						var arrParams = [address_definition_template_chash, device_address, signing_path];
						if (device_address === device.getMyDeviceAddress()){
							fields += ", address, device_addresses_by_relative_signing_paths, approval_date";
							values += ",?,?,"+db.getNow();
							arrParams.push(my_address, JSON.stringify(assocMyDeviceAddressesByRelativeSigningPaths));
						}
						db.query("INSERT INTO pending_shared_address_signing_paths ("+fields+") VALUES("+values+")", arrParams, function(){
							cb();
						});
					},
					function(){
						var arrMemberDeviceAddresses = _.uniq(_.values(assocMemberDeviceAddressesBySigningPaths));
						arrMemberDeviceAddresses.forEach(function(device_address){
							if (device_address !== device.getMyDeviceAddress())
								sendOfferToCreateNewSharedAddress(device_address, arrAddressDefinitionTemplate);
						})
					}
				);
			}
		);
	});
}
```

**File:** wallet_defined_by_addresses.js (L150-154)
```javascript
function approvePendingSharedAddress(address_definition_template_chash, from_address, address, assocDeviceAddressesByRelativeSigningPaths){
	db.query( // may update several rows if the device is referenced multiple times from the definition template
		"UPDATE pending_shared_address_signing_paths SET address=?, device_addresses_by_relative_signing_paths=?, approval_date="+db.getNow()+" \n\
		WHERE definition_template_chash=? AND device_address=?", 
		[address, JSON.stringify(assocDeviceAddressesByRelativeSigningPaths), address_definition_template_chash, from_address], 
```

**File:** wallet_defined_by_addresses.js (L229-234)
```javascript
// unused
function deletePendingSharedAddress(address_definition_template_chash){
	db.query("DELETE FROM pending_shared_address_signing_paths WHERE definition_template_chash=?", [address_definition_template_chash], function(){
		db.query("DELETE FROM pending_shared_addresses WHERE definition_template_chash=?", [address_definition_template_chash], function(){});
	});
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

**File:** wallet_defined_by_keys.js (L332-337)
```javascript
function deleteWallet(wallet, rejector_device_address, onDone){
	db.query("SELECT approval_date FROM extended_pubkeys WHERE wallet=? AND device_address=?", [wallet, rejector_device_address], function(rows){
		if (rows.length === 0) // you are not a member device
			return onDone();
		if (rows[0].approval_date) // you've already approved this wallet, you can't change your mind
			return onDone();
```
