## Title
Loss of pending outbox messages (private payment chains, signature requests) on device unpairing - (File: `device.js`, `wallet.js`)

### Summary
The `MessageProxy.removeConnectedChain` pattern — deleting a communication channel's pending message state without checking whether any messages are still queued for delivery — has a direct analog in ocore's device-pairing/unpairing flow. When a paired device is unpaired via the `removed_paired_device` protocol message, `removeCorrespondentDevice` unconditionally deletes all queued `outbox` messages addressed to that device, without checking whether any of those messages (e.g. forwarded private payment chains, signing requests, shared-address proposals) have actually been delivered yet.

### Finding Description
Unpairing is initiated remotely by the paired counterparty itself, an actor within the rules' scope ("paired device"). When device A receives a `removed_paired_device` message from device B, it calls `determineIfDeviceCanBeRemoved`: [1](#0-0) 

which only consults `readNonRemovableDevices`, checking `shared_address_signing_paths`, `wallet_signing_paths`, `pending_shared_address_signing_paths`, `prosaic_contracts`, `wallet_arbiter_contracts`, `arbiter_disputes`, and `arbiters`: [2](#0-1) 

None of these tables track the `outbox` table, which holds messages already queued for asynchronous/reliable delivery to a device (via `reliablySendPreparedMessageToHub`) but not yet acknowledged: [3](#0-2) 

Delivery is only removed from `outbox` once the hub responds `"accepted"`: [4](#0-3) 

Stalled/unacknowledged messages are otherwise periodically retried by `resendStalledMessages`: [5](#0-4) 

If `bRemovable` returns true, `removeCorrespondentDevice` is invoked, which unconditionally deletes every row from `outbox` addressed to that device before deleting the correspondent record: [6](#0-5) [7](#0-6) 

Because `outbox` is not part of the "non-removable" checks, any message that is queued for delivery to that peer but is not yet reflected in one of the checked tables (e.g. a forwarded private payment chain notification sent through `walletGeneral.forwardPrivateChainsToDevices` → `device.sendMessageToDevice` → `reliablySendPreparedMessageToHub`, or a signature request) is silently and permanently discarded the moment the counterparty unpairs, with no revert/refusal and no re-queue mechanism.

### Impact Explanation
Deleted outbox entries are gone forever — `resendStalledMessages` can only resend what is still present in `outbox`. If the deleted message was a forwarded private-payment chain (proof of a private asset transfer) or a required co-signing request for a shared/multisig address, the recipient never learns of the transfer or cannot participate in signing, which can result in loss/inaccessibility of private asset funds or funds stuck in a multisig/shared address whose cosigner never received the needed data. This matches the "AA/user fund loss or freezing" impact class analogous to the original MessageProxy finding (lost bridge messages carrying token transfers).

### Likelihood Explanation
The unpairing message (`removed_paired_device`) is fully attacker/self-controlled by the paired counterparty and requires no special privilege — it can be sent at any time, including immediately after a payment/notification has been queued but before it has been delivered/acknowledged, e.g. under network delay or when the recipient is offline (hub queues it) and the local outbox copy also still exists. The race window (queue message, then immediately unpair) is trivially reproducible by either party in the pairing relationship.

### Recommendation
Extend `readNonRemovableDevices` (or add an explicit check in `determineIfDeviceCanBeRemoved` / `removeCorrespondentDevice`) to verify there are no pending rows in `outbox` for the device address before allowing removal, and reject/queue the unpairing (or hold the correspondent record until outbox is drained) instead of deleting undelivered messages outright.

### Proof of Concept
1. Device A and Device B are paired.
2. A sends a private payment chain notification to B via `wallet_defined_by_addresses`/`walletGeneral.forwardPrivateChainsToDevices`, which calls `device.sendMessageToDevice` → `reliablySendPreparedMessageToHub`, inserting a row into `outbox` (`device.js:586-600`).
3. Before B's hub delivery is acknowledged (e.g., B is offline, or the request is delayed), B sends `removed_paired_device` to A.
4. A's `handleMessageFromHub` calls `determineIfDeviceCanBeRemoved(B, ...)` (`wallet.js:129`), which returns `true` because none of the checked tables reference B for this pending private-payment notification.
5. `device.removeCorrespondentDevice(B, ...)` executes `DELETE FROM outbox WHERE to=B` (`device.js:925`), permanently discarding the queued private payment chain message before it was ever delivered to B.

### Citations

**File:** wallet.js (L124-142)
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
			//	}
				break;
```

**File:** wallet.js (L2992-3011)
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
```

**File:** wallet.js (L3014-3022)
```javascript
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

**File:** device.js (L501-546)
```javascript
function resendStalledMessages(delay){
	delay = delay || 0;
	console.log("resending stalled messages delayed by "+delay+" minute");
	if (!network.isStarted())
		return console.log("resendStalledMessages: network not started yet");
	if (!objMyPermanentDeviceKey)
		return console.log("objMyPermanentDeviceKey not set yet, can't resend stalled messages");
	mutex.lockOrSkip(['stalled'], function(unlock){
		db.query(
			"SELECT "+(bCordova ? "LENGTH(message) AS len" : "message")+", message_hash, `to`, pubkey, hub \n\
			FROM outbox JOIN correspondent_devices ON `to`=device_address \n\
			WHERE outbox.creation_date<="+db.addTime("-"+delay+" MINUTE")+" ORDER BY outbox.creation_date", 
			function(rows){
				console.log(rows.length+" stalled messages");
				async.eachSeries(
					rows, 
					function(row, cb){
						if (!row.hub){ // weird error
							eventBus.emit('nonfatal_error', "no hub in resendStalledMessages: "+JSON.stringify(row)+", l="+rows.length, new Error('no hub'));
							return cb();
						}
						//	throw Error("no hub in resendStalledMessages: "+JSON.stringify(row));
						var send = async function(message) {
							if (!message) // the message is already gone
								return cb();
							var objDeviceMessage = JSON.parse(message);
							//if (objDeviceMessage.to !== row.to)
							//    throw "to mismatch";
							console.log('sending stalled '+row.message_hash);
							try {
								const err = await asyncCallWithTimeout(sendPreparedMessageToHub(row.hub, row.pubkey, row.message_hash, objDeviceMessage), 60e3);
								console.log('sending stalled ' + row.message_hash, 'err =', err);
							}
							catch (e) {
								console.log(`sending stalled ${row.message_hash} failed`, e);
							}
							cb();
						};
						bCordova ? readMessageInChunksFromOutbox(row.message_hash, row.len, send) : send(row.message);
					},
					unlock
				);
			}
		);
	});
}
```

**File:** device.js (L570-601)
```javascript
function reliablySendPreparedMessageToHub(ws, recipient_device_pubkey, json, callbacks, conn){
	var recipient_device_address = objectHash.getDeviceAddress(recipient_device_pubkey);
	console.log('will encrypt and send to '+recipient_device_address+': '+JSON.stringify(json));
	// encrypt to recipient's permanent pubkey before storing the message into outbox
	try {
		var objEncryptedPackage = createEncryptedPackage(json, recipient_device_pubkey);
	}
	catch (e) {
		return callbacks.ifError("failed to encrypt to permanent pubkey: " + e.toString());
	}
	// if the first attempt fails, this will be the inner message
	var objDeviceMessage = {
		encrypted_package: objEncryptedPackage
	};
	var message_hash = objectHash.getBase64Hash(objDeviceMessage);
	conn = conn || db;
	conn.query(
		"INSERT INTO outbox (message_hash, `to`, message) VALUES (?,?,?)", 
		[message_hash, recipient_device_address, JSON.stringify(objDeviceMessage)], 
		function(){
			if (callbacks && callbacks.onSaved){
				callbacks.onSaved();
				// db in resendStalledMessages will block until the transaction commits, assuming only 1 db connection
				// (fix if more than 1 db connection is allowed: in this case, it will send only after SEND_RETRY_PERIOD delay)
				process.nextTick(resendStalledMessages);
				// don't send to the network before the transaction commits
				return callbacks.ifOk ? callbacks.ifOk() : null;
			}
			sendPreparedMessageToHub(ws, recipient_device_pubkey, message_hash, json, callbacks);
		}
	);
}
```

**File:** device.js (L659-664)
```javascript
		network.sendRequest(ws, 'hub/deliver', objDeviceMessage, false, function(ws, request, response){
			if (response === "accepted"){
				db.query("DELETE FROM outbox WHERE message_hash=?", [message_hash], function(){
					callbacks.ifOk();
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
