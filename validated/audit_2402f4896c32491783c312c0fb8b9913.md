## Title
Race between async correspondent-device unpairing and in-flight multi-device wallet setup causes an uncaught assertion (DoS) - (File: wallet_defined_by_keys.js, wallet.js, device.js)

## Summary
The CVE-2023-3301 bug class is a TOCTOU race where an async "unplug"/removal path clears backend state that a concurrently-running "frontend" flow still assumes to exist, letting the frontend hit an unreachable/assertion state. In `ocore`, the analogous asynchronous removal path is the "correspondent device" unpairing flow (`removed_paired_device` message), which can race with the also-asynchronous multi-device wallet creation flow. The eligibility check used before unpairing does not account for a wallet-creation-in-progress window, so a correspondent can be deleted while it is still referenced by in-flight wallet state, and subsequent code paths that assume the correspondent still exists then `throw Error(...)` from inside an async DB callback — an uncaught exception that crashes the node process.

## Finding Description
When a paired device sends the `removed_paired_device` justsaying, the handler decides whether the correspondent can be safely dropped: [1](#0-0) 

The eligibility check `determineIfDeviceCanBeRemoved` delegates to `readNonRemovableDevices`, which unions several tables that "pin" a device as non-removable: [2](#0-1) 

Crucially, `readNonRemovableDevices` does **not** query `extended_pubkeys`, the table used to track cosigners during multisig wallet setup (`SELECT ... FROM shared_address_signing_paths ... UNION ... wallet_signing_paths ... UNION ... pending_shared_address_signing_paths ... UNION ... prosaic_contracts ... UNION ... wallet_arbiter_contracts ... UNION ... arbiter_disputes ...`).

Meanwhile, `addWallet` populates wallet state in two separate, sequential async steps: it inserts into `extended_pubkeys` first, and only afterwards inserts into `wallet_signing_paths`: [3](#0-2) 

This creates a genuine time window during which a cosigner device_address is recorded in `extended_pubkeys` (and thus semantically "in use" by the wallet) but is not yet present in `wallet_signing_paths` — the only per-device table checked by `readNonRemovableDevices`. If that same cosigner sends `removed_paired_device` during this window, `determineIfDeviceCanBeRemoved` wrongly reports the device as removable, and `device.removeCorrespondentDevice` deletes its `correspondent_devices` row: [4](#0-3) 

Later, when the wallet-setup flow tries to notify or look up that same cosigner — e.g. `checkAndFullyApproveWallet` sending `wallet_fully_approved` via `sendNotificationThatWalletFullyApproved`, or `readCosigners` validating that every `extended_pubkeys` row has a matching correspondent — the code assumes the correspondent still exists and throws: [5](#0-4) [6](#0-5) [7](#0-6) 

Because `sendMessageToDevice`/`sendMessageToHub` throw from inside an asynchronous `db.query` callback (not inside the synchronous call stack of the message handler's `try { doHandle(); } catch(e){...}` in `wallet.js`), the exception is not caught by the surrounding handler and becomes an unhandled exception in the event loop: [8](#0-7) 

This mirrors the QEMU CVE pattern: an async "unplug" (unpairing) clears backend state (`correspondent_devices` row) while a concurrent "frontend" flow (multi-device wallet setup, still holding an `extended_pubkeys` reference) has not finished, and the later dereference of the now-missing backend state trips an assertion (`throw Error`) that crashes the process.

## Impact Explanation
An uncaught exception thrown from an async DB callback in Node.js crashes the whole process, taking down the wallet/hub client node — a concrete denial of service triggered purely by message timing from an already-paired device, without needing any protocol-level double-spend or consensus violation. This matches the "Medium" severity, DoS-class impact of the CVE analog and is reachable by a paired device (an accepted actor per the campaign's threat model) simply by racing `removed_paired_device` against normal multi-device wallet creation traffic it is itself part of.

## Likelihood Explanation
The race requires a paired correspondent that is also a cosigner in a newly-initiated multisig wallet to send `removed_paired_device` in the narrow window between the `extended_pubkeys` insert and the `wallet_signing_paths` insert in `addWallet`, or more generally to send it before its own signing path is recorded. Since the paired device fully controls the timing of its own `removed_paired_device` message and can also drive the wallet-creation handshake (`my_xpubkey`, `wallet_fully_approved`) concurrently, it can intentionally interleave these messages, making the race practically triggerable rather than purely accidental.

## Recommendation
- Add `extended_pubkeys` (and any other table that references `device_address` before `wallet_signing_paths`/`shared_address_signing_paths` rows are written) to the `UNION` in `readNonRemovableDevices`, so a device with an in-flight wallet-setup reference cannot be judged removable.
- Alternatively/additionally, serialize `removeCorrespondentDevice` with wallet-creation mutations (e.g. under the same wallet-creation mutex key) so the eligibility check and the wallet-state writes cannot interleave.
- Wrap the `db.query` callback bodies in `device.sendMessageToDevice`/`sendMessageToHub` (and similar "assume correspondent exists" callbacks such as `readCosigners`) with graceful error handling instead of `throw Error(...)`, so a missing correspondent produces a handled error/event rather than an uncaught exception that terminates the process.

## Proof of Concept
1. Device A (hub client) initiates `createMultisigWallet` with device B as a cosigner; `addWallet` begins executing on A: the `extended_pubkeys` row for B is inserted, but the `wallet_signing_paths` insert for B has not yet completed (or A is still awaiting B's `my_xpubkey`/approval).
2. Device B, already paired with A and holding no other "non-removable" references (no `wallet_signing_paths`/`shared_address_signing_paths` row yet), sends `removed_paired_device` to A.
3. A's `handleMessageFromHub` calls `determineIfDeviceCanBeRemoved(B)` → `readNonRemovableDevices` does not see B (because it only checks `wallet_signing_paths`, not `extended_pubkeys`) → returns removable → `device.removeCorrespondentDevice(B)` deletes B's `correspondent_devices` row.
4. Shortly after, A's wallet-setup logic (`checkAndFullyApproveWallet` → `sendNotificationThatWalletFullyApproved` → `device.sendMessageToDevice(B, ...)`, or `readCosigners` for the wallet) executes and finds no `correspondent_devices` row for B, hitting `throw Error("correspondent not found")` / `throw Error("cosigner not found among correspondents...")` from inside an async `db.query` callback, crashing node A's process.

### Citations

**File:** wallet.js (L64-81)
```javascript
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	if (isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000))
		return callbacks.ifError("message from hub is too deeply nested or has too many nodes");

	// serialize all messages from hub
	mutex.lock(["from_hub"], function(unlock){
		var oldcb = callbacks;
		callbacks = {
			ifOk: function(){oldcb.ifOk(); unlock();},
			ifError: function(err){oldcb.ifError(err); unlock();}
		};
		try {
			doHandle();
		}
		catch (e) {
			callbacks.ifError("exception in handleMessageFromHub: " + e.toString());
		}
	});
```

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

**File:** wallet_defined_by_keys.js (L140-166)
```javascript
function checkAndFullyApproveWallet(wallet, onDone){
	db.query("SELECT approval_date FROM wallets LEFT JOIN extended_pubkeys USING(wallet) WHERE wallets.wallet=?", [wallet], function(rows){
		if (rows.length === 0) // wallet not created yet
			return onDone ? onDone() : null;
		if (rows.some(function(row){ return !row.approval_date; }))
			return onDone ? onDone() : null;
		db.query("UPDATE wallets SET full_approval_date="+db.getNow()+" WHERE wallet=? AND full_approval_date IS NULL", [wallet], function(){
			db.query(
				"UPDATE extended_pubkeys SET member_ready_date="+db.getNow()+" WHERE wallet=? AND device_address=?", 
				[wallet, device.getMyDeviceAddress()], 
				function(){
					db.query(
						"SELECT device_address FROM extended_pubkeys WHERE wallet=? AND device_address!=?", 
						[wallet, device.getMyDeviceAddress()], 
						function(rows){
							// let other members know that I've collected all necessary xpubkeys and ready to use this wallet
							rows.forEach(function(row){
								sendNotificationThatWalletFullyApproved(row.device_address, wallet);
							});
							checkAndFinalizeWallet(wallet, onDone);
						}
					);
				}
			);
		});
	});
}
```

**File:** wallet_defined_by_keys.js (L184-231)
```javascript
		function(cb){
			async.eachSeries(
				arrDeviceAddresses,
				function(device_address, cb2){
					console.log("adding device "+device_address+' to wallet '+wallet);
					var fields = "wallet, device_address";
					var values = "?,?";
					var arrParams = [wallet, device_address];
					// arrDeviceAddresses.length === 1 works for singlesig with external priv key
					if (device_address === device.getMyDeviceAddress() || arrDeviceAddresses.length === 1){
						fields += ", extended_pubkey, approval_date";
						values += ",?,"+db.getNow();
						arrParams.push(xPubKey);
						if (arrDeviceAddresses.length === 1){
							fields += ", member_ready_date";
							values += ", "+db.getNow();
						}
					}
					db.query("INSERT "+db.getIgnore()+" INTO extended_pubkeys ("+fields+") VALUES ("+values+")", arrParams, function(){
						cb2();
					});
				},
				cb
			);
		},
		function(cb){
			var arrSigningPaths = Object.keys(assocDeviceAddressesBySigningPaths);
			async.eachSeries(
				arrSigningPaths,
				function(signing_path, cb2){
					console.log("adding signing path "+signing_path+' to wallet '+wallet);
					var device_address = assocDeviceAddressesBySigningPaths[signing_path];
					db.query(
						"INSERT INTO wallet_signing_paths (wallet, signing_path, device_address) VALUES (?,?,?)", 
						[wallet, signing_path, device_address], 
						function(){
							cb2();
						}
					);
				},
				cb
			);
		}
	], function(){
		console.log("addWallet done "+wallet);
		(arrDeviceAddresses.length === 1) ? onDone() : checkAndFullyApproveWallet(wallet, onDone);
	});
}
```

**File:** wallet_defined_by_keys.js (L395-413)
```javascript
function readCosigners(wallet, handleCosigners){
	db.query(
		"SELECT extended_pubkeys.device_address, name, approval_date, extended_pubkey \n\
		FROM extended_pubkeys LEFT JOIN correspondent_devices USING(device_address) WHERE wallet=?", 
		[wallet], 
		function(rows){
			rows.forEach(function(row){
				if (row.device_address === device.getMyDeviceAddress()){
					if (row.name !== null)
						throw Error("found self in correspondents");
					row.me = true;
				}
				else if (row.name === null)
					throw Error("cosigner not found among correspondents, cosigner="+row.device_address+", my="+device.getMyDeviceAddress());
			});
			handleCosigners(rows);
		}
	);
}
```

**File:** device.js (L733-750)
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
}
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
