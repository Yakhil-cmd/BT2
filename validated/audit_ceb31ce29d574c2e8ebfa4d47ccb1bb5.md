### Title
TOCTOU race between correspondent-removability check and deletion lets a paired device permanently freeze a shared/multi-sig wallet or crash the node - ([File: device.js])

### Finding Description
The reference CVE is a use-after-free caused by a missing lock between an object's "remove" path and a concurrent handler that still uses the object. The closest reachable analog in ocore is a time-of-check-to-time-of-use (TOCTOU) race around correspondent-device removal, which is driven directly by messages from a paired device (an actor explicitly in scope per the rules).

When a paired device sends the `removed_paired_device` subject, `wallet.js`'s `handleMessageFromHub` dispatches to `determineIfDeviceCanBeRemoved`, which performs an async check (`readNonRemovableDevices`) against `shared_address_signing_paths`, `wallet_signing_paths`, `pending_shared_address_signing_paths`, `prosaic_contracts`, etc., and only if the device is not referenced anywhere does it call `device.removeCorrespondentDevice`, which deletes the row from `correspondent_devices` (and the pending `outbox`). [1](#0-0) [2](#0-1) [3](#0-2) 

Although `handleMessageFromHub` serializes processing of hub messages under `mutex.lock(["from_hub"])`, the check-then-delete sequence (`readNonRemovableDevices` → `removeCorrespondentDevice`) is not atomic with respect to *other* code paths that create new dependencies on the same `device_address` (e.g., a concurrently in-progress shared-address/multisig wallet setup that inserts rows into `pending_shared_address_signing_paths` or `shared_address_signing_paths` in `wallet_defined_by_addresses.js`, which run outside the `from_hub` mutex). A device can be marked removable at check time, have its correspondent row deleted, and only afterward have a new signing-path dependency inserted that references the now-deleted correspondent.

Once the correspondent record is gone, any later attempt to message that device — e.g., to request a co-signature for the shared address the wallet just created — goes through `sendMessageToDevice`, which unconditionally throws `Error("correspondent not found")` when `conf.bIgnoreMissingCorrespondents` is not set: [4](#0-3) 

This is analogous to the kernel bug class: cleanup of a shared resource races with concurrent code that still depends on it, and the missing synchronization results in either (a) an uncaught exception that crashes the node process (since it's a synchronous `throw` inside a DB callback, not routed through the normal `ifError` callback chain), or (b) a shared/multisig address permanently missing one of its correspondent records, so the required co-signer can never be reached — permanently freezing any funds sent to that shared address.

### Impact Explanation
- If the process throws an uncaught `Error("correspondent not found")`, it crashes the entire node/wallet process (denial of service for that user's wallet/hub session).
- If a shared address was created with a co-signer whose correspondent record was just removed by the TOCTOU race, no further signing requests can ever reach that co-signer, permanently freezing coins sent to that shared address (fund-freezing impact, matching the "AA fund loss or freezing" acceptance criterion, generalized to any shared-address wallet fund).

### Likelihood Explanation
The trigger — a `removed_paired_device` justsaying — is fully controlled by any device the victim has paired with, which the rules explicitly treat as an in-scope, reachable actor. Winning the race requires the attacker (or a legitimately fast wallet operation) to interleave a new shared-address setup with the removability check window, which is plausible in an actively used wallet doing simultaneous multi-device co-signing, though it does require timing luck, keeping likelihood moderate rather than trivial.

### Recommendation
Make the removability check and the correspondent deletion atomic with respect to shared-address/signing-path creation: perform both the `readNonRemovableDevices` check and the `DELETE FROM correspondent_devices` inside a single transaction/mutex that is also held (or re-checked) by the code paths in `wallet_defined_by_addresses.js` that insert new rows into `shared_address_signing_paths` / `pending_shared_address_signing_paths` for a given `device_address`. Additionally, `sendMessageToDevice` should not `throw` synchronously on a missing correspondent; it should surface the error through the normal callback (`callbacks.ifError`) so callers can handle a vanished correspondent gracefully instead of crashing the process.

### Proof of Concept
1. Pair device B with local wallet A.
2. Have B (attacker-controlled) send `removed_paired_device` to A at the same moment A independently begins creating a new shared address that includes B as a cosigner (inserting into `pending_shared_address_signing_paths`).
3. A's `determineIfDeviceCanBeRemoved` check for B completes before the new signing-path row is committed, returning "removable"; A deletes B's correspondent record via `removeCorrespondentDevice`.
4. The shared-address creation subsequently commits, referencing B as a required cosigner, but B no longer has a `correspondent_devices` row.
5. When A later calls `device.sendMessageToDevice(B, ...)` to request B's signature, `sendMessageToDevice` throws `Error("correspondent not found")`, crashing A's process; the shared address's funds can never be spent because B can never be reached again to co-sign.

### Citations

**File:** wallet.js (L124-140)
```javascript
			case "removed_paired_device":
			//	if(conf.bIgnoreUnpairRequests) {
			//		// unpairing is ignored
			//		callbacks.ifError("removed_paired_device ignored: "+from_address);
			//	} else {
					determineIfDeviceCanBeRemoved(from_address, function(bRemovable){
						if (!bRemovable)
							return callbacks.ifError("device "+from_address+" is not removable");
						if (conf.bIgnoreUnpairRequests){
							db.query("UPDATE correspondent_devices SET is_blackhole=1 WHERE device_address=?", [from_address]);
							return callbacks.ifOk();
						}
						device.removeCorrespondentDevice(from_address, function(){
							eventBus.emit("removed_paired_device", from_address);
							callbacks.ifOk();
						});
					});
```

**File:** wallet.js (L2992-3022)
```javascript
function readNonRemovableDevices(onDone){

	var sql = "SELECT DISTINCT device_address FROM shared_address_signing_paths ";
	sql += "UNION SELECT DISTINCT device_address FROM wallet_signing_paths ";
	sql += "UNION SELECT DISTINCT device_address FROM pending_shared_address_signing_paths ";
	sql += "UNION SELECT DISTINCT peer_device_address AS device_address FROM prosaic_contracts ";
	sql += "UNION SELECT DISTINCT peer_device_address AS device_address FROM wallet_arbiter_contracts ";
	sql += "UNION SELECT DISTINCT arbstore_device_address AS device_address FROM arbiter_disputes ";
	if (conf.ArbStoreWebURI)
		sql += "UNION SELECT DISTINCT device_address AS device_address FROM arbiters";
	
	db.query(
		sql, 
		function(rows){
			
			var arrDeviceAddress = rows.map(function(r) { return r.device_address; });

			onDone(arrDeviceAddress);
		}
	);
}

function determineIfDeviceCanBeRemoved(device_address, handleResult) {
	device.readCorrespondent(device_address, function(correspondent){
		if (!correspondent)
			return handleResult(false);
		readNonRemovableDevices(function(arrDeviceAddresses){
			handleResult(arrDeviceAddresses.indexOf(device_address) === -1);
		});
	});
};
```

**File:** device.js (L733-749)
```javascript
function sendMessageToDevice(device_address, subject, body, callbacks, conn){
	if (!device_address)
		throw Error("empty device address");
	conn = conn || db;
	conn.query("SELECT hub, pubkey, is_blackhole FROM correspondent_devices WHERE device_address=?", [device_address], function(rows){
		if (rows.length !== 1 && !conf.bIgnoreMissingCorrespondents)
			throw Error("correspondent not found");
		if (rows.length === 0 && conf.bIgnoreMissingCorrespondents || rows[0].is_blackhole){
			console.log(rows.length === 0 ? "ignoring missing correspondent " + device_address : "not sending to " + device_address + " which is set as blackhole");
			if (callbacks && callbacks.onSaved)
				callbacks.onSaved();
			if (callbacks && callbacks.ifOk)
				callbacks.ifOk();
			return;
		}
		sendMessageToHub(rows[0].hub, rows[0].pubkey, subject, body, callbacks, conn);
	});
```

**File:** device.js (L922-930)
```javascript
function removeCorrespondentDevice(device_address, onDone){
	breadcrumbs.add('correspondent removed: '+device_address);
	var arrQueries = [];
	db.addQuery(arrQueries, "DELETE FROM outbox WHERE `to`=?", [device_address]);
	db.addQuery(arrQueries, "DELETE FROM correspondent_devices WHERE device_address=?", [device_address]);
	async.series(arrQueries, onDone);
	if (bCordova)
		updateCorrespondentSettings(device_address, {push_enabled: 0});
}
```
