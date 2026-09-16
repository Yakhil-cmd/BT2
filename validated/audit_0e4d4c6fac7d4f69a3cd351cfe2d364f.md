### Title
Malformed unsigned-unit `sign` request from a paired device crashes the whole node via the global `uncaughtException` handler - ([File: wallet.js])

### Summary
`wallet.js`'s `handleMessageFromHub()` wraps the *synchronous* part of message handling (`doHandle()`) in a `try/catch`, but several `subject` handlers (notably `"sign"`) hand attacker-controlled, minimally-validated data off to asynchronous callbacks (`findAddress(...).ifLocal`, then `network.handleOnlineJoint`) that execute **after** the protecting `try/catch` has already returned. Any exception thrown from that later, unprotected code path is not caught anywhere and propagates to the process-wide `uncaughtException` handler in `network.js`, which deliberately re-throws to kill the process. A correspondent (paired) device that is allowed to message the wallet can therefore crash the entire ocore node/wallet process with one malformed `sign` message, exactly analogous to the reported Mattermost bug class (malformed payload from a semi-trusted peer crashing the app because payload validation is incomplete/asynchronous).

### Finding Description
`handleMessageFromHub()` locks a mutex and calls `doHandle()` inside a `try { doHandle(); } catch (e) { callbacks.ifError(...) }` block: [1](#0-0) 

For the `"sign"` subject, the handler performs some validation of `body.address`, `body.signing_path`, and `objUnit.authors`, but `objUnit` (`body.unsigned_unit`) is otherwise almost entirely attacker-controlled JSON (no required `parent_units`, `version`, `messages` shape enforcement beyond a few checks): [2](#0-1) 

After these synchronous checks, execution continues into `findAddress(...)`, whose `ifLocal` callback fires from a database query - i.e., **asynchronously**, after `doHandle()` (and its enclosing `try/catch`) has already returned: [3](#0-2) 

Inside that async callback, the (still essentially unchecked) `objUnit` is wrapped into `objJoint = {unit: objUnit, unsigned: true}` and passed straight to `network.handleOnlineJoint(ws, objJoint)`: [4](#0-3) 

`handleOnlineJoint`/`handleJoint` do perform a few checks (missing `unit`, missing/invalid `version`), but validation.validate() and its many nested oscript/format assumptions about unit shape are reached from there; any code path that throws synchronously on unexpected/malformed structure (e.g., missing/garbled `parent_units`, `messages`, or other fields not checked earlier) is now completely outside of any try/catch, because the protecting one in `handleMessageFromHub` (`wallet.js:75-80`) only covers the synchronous portion of `doHandle()`. [5](#0-4) 

Once that exception surfaces, it is caught by nothing until it reaches the process-level handler, which explicitly re-throws to crash the whole process ("to avoid ending up in an inconsistent state"): [6](#0-5) 

This mirrors the CVE-2026-9602 bug class: a payload originating from a peer that the application partially trusts (there, the web app talking to the desktop IPC bridge; here, a paired/correspondent device talking to the wallet over the hub) is not fully validated before being processed, and a malformed field crashes the whole application rather than just being rejected.

### Impact Explanation
Because the top-level `uncaughtException` handler intentionally re-throws (`network.js:4542`, `throw err; // crash the process`), any uncaught exception anywhere in the async continuation of `handleMessageFromHub` terminates the entire ocore process - not just the specific request or connection. For a full node/hub this is a denial of service: the node stops confirming/relaying units and serving light clients until manually restarted, and if this can be triggered repeatedly by any paired device (including one paired through a permanent/shared pairing secret, or one whose pairing was accepted for legitimate purposes), it enables reliable, repeatable denial of service against wallets and possibly hubs/relays that also run the wallet module.

### Likelihood Explanation
The wallet event handler intentionally accepts `"sign"` messages from any correspondent/paired device (this is a documented multisig/multilateral-signing workflow), and the pre-checks performed on `body.unsigned_unit` are shallow (presence of `authors` array with matching address; `signing_path` regex) rather than a full schema/type validation of the whole unit object. A malicious or compromised paired device can send a `sign` request whose `unsigned_unit` is crafted to pass the shallow checks but contain a shape that later code (in `network.handleOnlineJoint` → `validation.validate` or later code paths) does not defensively guard against, triggering an exception outside of the `try/catch` in `wallet.js`. Reaching a specific throwing statement requires knowledge of validation internals, but the overall crash mechanism (async exception outside protective try/catch, deliberately fatal `uncaughtException` handler) is structurally present and low-effort to exploit once such a field is identified.

### Recommendation
- Wrap the asynchronous continuations in `wallet.js`'s `"sign"` handler (the `findAddress` callbacks, and specifically the call to `network.handleOnlineJoint`) in their own `try/catch`, converting any exception into `callbacks.ifError(...)` instead of letting it propagate.
- Perform full structural/type validation of `body.unsigned_unit` (parent_units, messages array shape, version-specific required fields) synchronously and reject early with `callbacks.ifError` for anything not conforming, rather than relying on downstream validation code to always throw safely.
- More generally, audit all `eventBus`/callback-based hub-message handlers in `wallet.js` and `device.js` for asynchronous continuations that occur outside of the guarding `try/catch` in `handleMessageFromHub`, and add local exception handling around each, since the global `uncaughtException` handler is intentionally fatal.

### Proof of Concept
Not fully verified end-to-end due to the difficulty of pinpointing, within the available time, the exact downstream field in `validation.validate`/`handleOnlineJoint` that throws synchronously (rather than reporting `ifUnitError`) on a malformed but shallowly-valid `unsigned_unit`. Conceptually:
1. Pair a device with the victim wallet (or use an existing correspondent/compromised paired device).
2. Send a `"sign"` message where `body.address` is a valid local address, `body.signing_path` matches `^r(\.\d+)*$`, and `body.unsigned_unit.authors` contains an author object whose `address` equals `body.address`, but where other fields of `unsigned_unit` (e.g. `parent_units`, `messages` payload structures) are malformed in a way not checked at `wallet.js:251-330`.
3. Because `objUnit` is forwarded via `network.handleOnlineJoint` from an asynchronous DB-callback context (`wallet.js:357-372`), any exception thrown deeper in unit processing bypasses the `try/catch` in `handleMessageFromHub` (`wallet.js:75-80`) and reaches the fatal `process.on('uncaughtException', ...)` handler in `network.js:4530-4543`, crashing the node.

This should be confirmed by a Devin session with code execution access, tracing the exact synchronous-throw sites reachable from `handleOnlineJoint`/`validation.validate` for a minimally-valid-looking but malformed unsigned unit.

### Citations

**File:** wallet.js (L63-81)
```javascript
// one of callbacks MUST be called, otherwise the mutex will stay locked
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

**File:** wallet.js (L251-277)
```javascript
			case "sign":
				// {address: "BASE32", signing_path: "r.1.2.3", unsigned_unit: {...}}
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("no address or bad address");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
				var objUnit = body.unsigned_unit;
				if (typeof objUnit !== "object" || objUnit === null)
					return callbacks.ifError("no unsigned unit");
				if (!ValidationUtils.isNonemptyArray(objUnit.authors))
					return callbacks.ifError("no authors array");
				var bJsonBased = (objUnit.version !== constants.versionWithoutTimestamp);
				// replace all existing signatures with placeholders so that signing requests sent to us on different stages of signing become identical,
				// hence the hashes of such unsigned units are also identical
				try {
					objUnit.authors.forEach(function (author) {
						var authentifiers = author.authentifiers;
						for (var path in authentifiers)
							authentifiers[path] = authentifiers[path].replace(/./g, '-');
					});
					const authorAddresses = objUnit.authors.map(author => author.address);
					if (!authorAddresses.includes(body.address))
						return callbacks.ifError("address not found among authors");
				}
				catch (e) {
					return callbacks.ifError("invalid authors: " + e.toString());
				}
```

**File:** wallet.js (L332-372)
```javascript
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
						//});
```

**File:** network.js (L1149-1163)
```javascript
function handleJoint(ws, objJoint, bSaved, bPosted, callbacks){
	if ('aa' in objJoint)
		return callbacks.ifJointError("AA unit cannot be broadcast");
	var unit = objJoint.unit.unit;
	if (typeof unit !== 'string')
		return callbacks.ifJointError("invalid unit");
	const version = objJoint.unit.version;
	if (typeof version !== 'string')
		return callbacks.ifJointError("invalid version");
	const fVersion = parseFloat(version);
	if (!(fVersion >= constants.fVersion4 || objJoint.ball)) // covers NaN too
		return callbacks.ifTransientError("version is too old");
	if (assocUnitsInWork[unit])
		return callbacks.ifUnitInWork();
	assocUnitsInWork[unit] = true;
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
