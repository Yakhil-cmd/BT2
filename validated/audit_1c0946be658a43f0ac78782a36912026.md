## Analysis

The audit finding concerns a commented-out `require` check in `TokenDistribution.sol` that was supposed to restrict a "claim" action to the address owner, but is disabled — letting anyone perform the privileged action on behalf of another account. The direct structural analog in `ocore--016` is a commented-out cosigner-authorization check inside the `"sign"` message handler in `wallet.js`, reached from any paired device.

### Title
Missing cosigner authorization check lets any paired device request signing on behalf of another wallet's address - (File: wallet.js)

### Summary
In the `"sign"` case of `handleMessageFromHub()`, when the requested signing address resolves to a locally-held key (`findAddress`'s `ifLocal` callback), the code is supposed to verify that the requesting paired device (`from_address`) is actually a registered cosigner of the target wallet before honoring the signing request. That verification query is commented out, so the check is never performed.

### Finding Description
The `"sign"` message is processed for any correspondent device paired with the node/wallet [1](#0-0) . After minimal structural validation of the unsigned unit and address membership among the unit's authors, `findAddress` is used to resolve the target address; when it is a locally-held key, `ifLocal` is invoked [2](#0-1) . The intended cosigner check — verifying that `from_address` is listed in `extended_pubkeys` for the address's `wallet` — is commented out with the explicit note that leaving it disabled is required for "multilateral signing" to keep working [3](#0-2) . As written, once the commented block is skipped, `callbacks.ifOk()` fires and the unsigned unit (or signed_message) is passed straight into the `"signing_request"` event pipeline, which drives the wallet UI's confirmation dialog and eventually into `network.handleOnlineJoint` [4](#0-3) .

`findAddress` shows that `ifLocal` is reached not just for single-key wallet addresses, but recursively for any locally-hosted member key underneath shared/multisig addresses as well, since shared addresses defer to the same function [5](#0-4) [6](#0-5) . The `extended_pubkeys` table exists specifically to record which device addresses are legitimate cosigners of a given wallet [7](#0-6) , confirming that the commented query was the intended authorization gate.

### Impact Explanation
With the check disabled, *any* device merely paired as a correspondent (not necessarily a cosigner of the target wallet) can send a crafted `"sign"` request naming one of the user's own addresses and an arbitrary `unsigned_unit`/`signed_message` payload. The node will process it as if it came from a legitimate cosigner and raise a `"signing_request"` UI event for the user to approve — bypassing the intended restriction that only actual wallet cosigners should be able to initiate such requests. This widens the trust boundary for who can push spend/sign proposals at a locally-held key from "verified cosigners of that specific wallet" to "any paired device," which is precisely the same class of issue as the audited bug: a disabled ownership/authorization check that changes an operation from "self/authorized-party only" to "anyone can invoke on your behalf."

### Likelihood Explanation
Reachable by any already-paired correspondent device without further privilege — pairing with a wallet is a routine, low-barrier interaction (e.g., via pairing code exchange for chats, textcoins, contracts). No additional access or on-chain state is required to trigger the code path; only the final signature act still needs user interaction in the wallet UI, but the authorization gate that should filter out illegitimate requesters before that point is absent.

### Recommendation
Restore (or replace with an equivalent async/await version) the commented cosigner check in the `ifLocal` branch of the `"sign"` case in `wallet.js`, verifying `from_address` is a legitimate device for the target wallet in `extended_pubkeys` before proceeding to `callbacks.ifOk()` and emitting `"signing_request"`. If multilateral signing genuinely requires accepting requests from non-cosigner devices in some legitimate flow, that flow should be explicitly modeled (e.g., a distinct message subject or a separate authorization list) rather than disabling the general cosigner check for all `"sign"` requests.

### Proof of Concept
1. Pair device `M` (malicious) with victim's node as a normal correspondent (e.g., via a pairing code from a chat/support flow).
2. From `M`, send a `"sign"` justsaying/request message: `{address: <victim_local_address>, signing_path: "r", unsigned_unit: {authors: [{address: victim_local_address, authentifiers: {...}}], messages: [...]}}`.
3. `handleMessageFromHub` validates structure only, resolves `victim_local_address` via `findAddress` to `ifLocal`, and — because the cosigner check is commented out — proceeds directly to `callbacks.ifOk()` and fires `"signing_request"`, presenting the victim's wallet UI with a plausible-looking cosign/confirmation prompt for `M`'s crafted transaction, even though `M` was never registered as a cosigner of that wallet. [8](#0-7)

### Citations

**File:** wallet.js (L251-256)
```javascript
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
```

**File:** wallet.js (L331-371)
```javascript
				// findAddress handles both types of addresses
				findAddress(body.address, body.signing_path, {
					ifError: callbacks.ifError,
					ifLocal: function(objAddress){
						// the commented check would make multilateral signing impossible
						//db.query("SELECT 1 FROM extended_pubkeys WHERE wallet=? AND device_address=?", [row.wallet, from_address], function(sender_rows){
						//    if (sender_rows.length !== 1)
						//        return callbacks.ifError("sender is not cosigner of this address");
							callbacks.ifOk();
							if (objUnit.signed_message && !ValidationUtils.hasFieldsExcept(objUnit, ["signed_message", "authors", "version"])){
								try {
									objUnit.unit = objectHash.getBase64Hash(objUnit); // exact value doesn't matter, it just needs to be there
								}
								catch (e) {
									console.log("signed message hash failed", e);
									objUnit.unit = "failedunit";
								}
								return eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							}
							try {
								objUnit.unit = objectHash.getUnitHash(objUnit);
							}
							catch (e) {
								console.log("to-be-signed unit hash failed", e);
								return;
							}
							var objJoint = {unit: objUnit, unsigned: true};
							eventBus.once("validated-"+objUnit.unit, function(bValid){
								if (!bValid){
									console.log("===== unit in signing request is invalid");
									return;
								}
								// This event should trigger a confirmation dialog.
								// If we merge coins from several addresses of the same wallet, we'll fire this event multiple times for the same unit.
								// The event handler must lock the unit before displaying a confirmation dialog, then remember user's choice and apply it to all
								// subsequent requests related to the same unit
								eventBus.emit("signing_request", objAddress, body.address, objUnit, assocPrivatePayloads, from_address, body.signing_path);
							});
							// if validation is already under way, handleOnlineJoint will quickly exit because of assocUnitsInWork.
							// as soon as the previously started validation finishes, it will trigger our event handler (as well as its own)
							network.handleOnlineJoint(ws, objJoint);
```

**File:** wallet.js (L1233-1259)
```javascript
function findAddress(address, signing_path, callbacks, fallbackInfo){
	db.query(
		"SELECT wallet, account, is_change, address_index, full_approval_date, device_address \n\
		FROM my_addresses JOIN wallets USING(wallet) JOIN wallet_signing_paths USING(wallet) \n\
		WHERE address=? AND signing_path=?",
		[address, signing_path],
		async function(rows){
			if (rows.length > 1)
				throw Error("more than 1 address found");
			if (rows.length === 1){
				var row = rows[0];
				if (!row.full_approval_date)
					return callbacks.ifError("wallet of address "+address+" not approved");
				if (row.device_address !== device.getMyDeviceAddress()) {
					const other_rows = await db.query("SELECT DISTINCT device_address FROM wallet_signing_paths WHERE wallet=? AND device_address!=?", [row.wallet, row.device_address]);
					const other_device_addresses = other_rows.map(r => r.device_address);
					return callbacks.ifRemote(row.device_address, other_device_addresses);
				}
				var objAddress = {
					address: address,
					wallet: row.wallet,
					account: row.account,
					is_change: row.is_change,
					address_index: row.address_index
				};
				callbacks.ifLocal(objAddress);
				return;
```

**File:** wallet.js (L1271-1287)
```javascript
					if (sa_rows.length === 1) {
						var objSharedAddress = sa_rows[0];
						var relative_signing_path = 'r' + signing_path.substr(objSharedAddress.signing_path.length);
						var bLocal = (objSharedAddress.device_address === device.getMyDeviceAddress()); // local keys
						if (objSharedAddress.address === '') {
							return callbacks.ifMerkle(bLocal);
						} else if(objSharedAddress.address === 'secret') {
							return callbacks.ifSecret();
						}
						let newFallbackInfo = null;
						if (!bLocal) {
							newFallbackInfo = {};
							newFallbackInfo.device_address = objSharedAddress.device_address;
							const other_rows = await db.query("SELECT DISTINCT device_address FROM shared_address_signing_paths WHERE shared_address=? AND device_address!=?", [address, objSharedAddress.device_address]);
							newFallbackInfo.other_device_addresses = other_rows.map(r => r.device_address);
						}
						return findAddress(objSharedAddress.address, relative_signing_path, callbacks, newFallbackInfo);
```

**File:** initial-db/byteball-sqlite.sql (L572-582)
```sql
CREATE TABLE extended_pubkeys (
	wallet CHAR(44) NOT NULL, -- no FK because xpubkey may arrive earlier than the wallet is approved by the user and written to the db
	extended_pubkey CHAR(112) NULL, -- base58 encoded, see bip32, NULL while pending
	device_address CHAR(33) NOT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	approval_date TIMESTAMP NULL,
	member_ready_date TIMESTAMP NULL, -- when this member notified us that he has collected all member xpubkeys
	PRIMARY KEY (wallet, device_address)
	-- own address is not present in correspondents
--    FOREIGN KEY byDeviceAddress(device_address) REFERENCES correspondent_devices(device_address)
);
```
