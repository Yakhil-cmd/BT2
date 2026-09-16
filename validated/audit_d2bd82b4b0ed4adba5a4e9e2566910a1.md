### Title
Unhandled exception from unvalidated numeric header field crashes the node - (File: `validation.js`, `object_length.js`)

### Summary
`validation.js`'s `validate()` function calls `objectLength.getHeadersSize(objUnit)` without a surrounding `try/catch`, unlike the very next check (`getTotalPayloadSize`) which is explicitly wrapped. `getHeadersSize()` runs `object_length.js`'s `getLength()` over the unit's header fields — including `earned_headers_commission_recipients`, which has **not yet been structurally validated** at that point in `validate()` (its dedicated validator, `validateHeadersCommissionRecipients`, only runs later inside the `async.series` pipeline). If any numeric value in that unvalidated field overflows to `Infinity` (a value like `1e400` is syntactically valid JSON and `JSON.parse` legally turns it into `Infinity`), `getLength()` throws synchronously and uncaught. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`validate()` is entered directly with the network-supplied `objJoint`; the "serial unit" branch computes and compares `objectLength.getHeadersSize(objUnit)` against `objUnit.headers_commission` before `objUnit.authors`, `parent_units`, timestamp/version, or `earned_headers_commission_recipients` are structurally checked: [4](#0-3) [5](#0-4) 

`getHeadersSize()` clones the whole unit minus a few stripped fields (leaving `authors`, `witness_list_unit`, `witnesses`, `earned_headers_commission_recipients`, `last_ball`, `last_ball_unit`, `tps_fee`, `burn_fee`, `max_aa_responses`, etc.) and feeds it to `getLength()`: [3](#0-2) 

`getLength()` throws `Error("invalid number: " + value)` for any non-finite number: [2](#0-1) 

`tps_fee`, `burn_fee`, and `max_aa_responses` are already validated to be finite integers earlier in `validate()`, so they cannot carry `Infinity`. However, `earned_headers_commission_recipients` is only validated later, inside `validateHeadersCommissionRecipients`, which runs asynchronously after `getHeadersSize()` has already executed: [6](#0-5) 

Because JSON text like `1e400` parses to `Infinity` in JavaScript's `JSON.parse`, an attacker can place such a value inside a numeric field of `earned_headers_commission_recipients` (e.g. the commission share) and have it survive untouched to the point `getHeadersSize()` walks the object tree, triggering the uncaught throw.

This throw is **synchronous** and happens directly inside `validate()`'s top-level execution, which in `network.js` is invoked directly (not wrapped in try/catch) from inside `mutex.lock`'s synchronous `exec()` call: [7](#0-6) [8](#0-7) [9](#0-8) 

`exec()` calls `proc(unlock)` synchronously with no try/catch, so the exception propagates out through `handleJoint`, out through the WebSocket `'message'` event dispatch, and becomes an uncaught exception at the process level. The registered handler for that case explicitly re-throws to crash the process: [10](#0-9) 

This mirrors the CVE-2018-7262 bug class: a piece of attacker-supplied structured input (there, an HTTP header; here, a numeric field of a broadcast unit) is not sanity-checked before being consumed by a lower-level parser/length routine, and the resulting unhandled failure crashes the service rather than being rejected gracefully as a validation error.

### Impact Explanation
Any single crafted unit broadcast to the network (or posted by a light client through a full/hub node) reaches `handleJoint`/`validation.validate` on every peer that receives it. The uncaught exception crashes the node process on each recipient, matching the “network unable to confirm new units” impact class — a remote, unauthenticated, single-message denial of service against any full node/hub that processes the malicious joint.

### Likelihood Explanation
High. No special privileges, keys, or peer control are needed — just crafting one JSON unit with a numeric literal like `1e400` inside an as-yet-unvalidated field and getting it accepted into `handleJoint`/`validate()`. It does not require the unit to otherwise be valid (author signatures, parents, etc. are never checked because the crash happens earlier in `validate()`, before `validateAuthors`/`validateParents`/`validateHeadersCommissionRecipients` run).

### Recommendation
Wrap the `objectLength.getHeadersSize(objUnit)` call in `validation.js` in the same `try/catch` pattern already used for `getTotalPayloadSize`, converting any thrown error into `callbacks.ifJointError(...)`/`ifUnitError(...)` instead of letting it propagate. Additionally, harden `object_length.js`'s `getLength()` (or add an early guard in `validate()`) to treat non-finite numbers found anywhere in the unit as a joint error rather than throwing, and consider moving/duplicating `earned_headers_commission_recipients` type validation before `getHeadersSize()` is invoked.

### Proof of Concept
1. Construct a syntactically well-formed unit JSON (`objJoint.unit`) with correct `unit`, `version`, `authors` shape sufficient to pass earlier length/array checks, and add:
```json
"earned_headers_commission_recipients": [
  { "address": "SOME32CHARBASE32ADDRESS........", "earned_headers_commission_share": 1e400 }
]
```
2. Ensure the computed `headers_commission`/other prior checks are satisfiable enough to reach line 257 in `validate()` (i.e., pass all checks up through the messages-hash loop).
3. Broadcast this joint to a full node/hub over the P2P WebSocket protocol as a normal `justsaying`/`request` "new joint" message, or POST it via a light-vendor endpoint.
4. On the receiving node, `validation.validate()` reaches `objectLength.getHeadersSize(objUnit)` → `getLength()` encounters `1e400` (parsed as `Infinity`) → throws `Error("invalid number: Infinity")` synchronously, uncaught by `validate()`'s callers, triggering `process.on('uncaughtException')` → `throw err` → node process crash.

### Citations

**File:** validation.js (L189-218)
```javascript
	else{ // serial
		if (hasFieldsExcept(objUnit, ["unit", "version", "alt", "timestamp", "authors", "messages", "witness_list_unit", "witnesses", "earned_headers_commission_recipients", "last_ball", "last_ball_unit", "parent_units", "headers_commission", "payload_commission", "oversize_fee", "tps_fee", "burn_fee", "max_aa_responses"]))
			return callbacks.ifUnitError("unknown fields in unit");

		if (typeof objUnit.headers_commission !== "number")
			return callbacks.ifJointError("no headers_commission");
		if (typeof objUnit.payload_commission !== "number")
			return callbacks.ifJointError("no payload_commission");
		if ("oversize_fee" in objUnit && !isPositiveInteger(objUnit.oversize_fee))
			return callbacks.ifJointError("bad oversize_fee");
		if ("tps_fee" in objUnit && !isNonnegativeInteger(objUnit.tps_fee))
			return callbacks.ifUnitError("bad tps_fee");
		if ("burn_fee" in objUnit && !isPositiveInteger(objUnit.burn_fee))
			return callbacks.ifUnitError("bad burn_fee");
		if ("max_aa_responses" in objUnit) {
			if (!isNonnegativeInteger(objUnit.max_aa_responses))
				return callbacks.ifUnitError("bad max_aa_responses");
			if (objUnit.max_aa_responses > constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER && !(constants.bTestnet && ['pLpKQaXTTgcpFrd8B1zvcw2dLcDAvaUkQuz1fY+ldPA=', 'J/8gMqNqIkq2LIPV7rQNjWk37u16/P7nToV+SSZxMDs='].includes(objUnit.unit)))
				return callbacks.ifTransientError("max_aa_responses too large"); // later: ifUnitError
			if (objUnit.max_aa_responses === 0 && !("ball" in objJoint))
				return callbacks.ifTransientError("max_aa_responses=0 not allowed in new units");
		}
		
		if (!isNonemptyArray(objUnit.messages))
			return callbacks.ifUnitError("missing or empty messages array");
		if (objUnit.messages.length > constants.MAX_MESSAGES_PER_UNIT && !bGenesis)
			return callbacks.ifUnitError("too many messages");
		if (!objUnit.messages.every(isNonemptyObject))
			return callbacks.ifUnitError("all messages must be non-empty objects");

```

**File:** validation.js (L257-269)
```javascript
		if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
			return callbacks.ifJointError("wrong headers commission, expected "+objectLength.getHeadersSize(objUnit));
		try {
			const payloadSize = objectLength.getTotalPayloadSize(objUnit);
			if (payloadSize !== objUnit.payload_commission)
				return callbacks.ifJointError("wrong payload commission, unit " + objUnit.unit + ", expected " + payloadSize);
		}
		catch (e) {
			return callbacks.ifJointError("failed to calculate payload commission: " + e);
		}
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
	}
```

**File:** validation.js (L385-389)
```javascript
				function(cb){
					profiler.stop('validation-checkDuplicate');
					profiler.start();
					objUnit.content_hash ? cb() : validateHeadersCommissionRecipients(objUnit, cb);
				},
```

**File:** object_length.js (L14-20)
```javascript
		switch (typeof value) {
			case "string":
				return value.length;
			case "number":
				if (!isFinite(value))
					throw Error("invalid number: " + value);
				return 8;
```

**File:** object_length.js (L52-69)
```javascript
function getHeadersSize(objUnit) {
	if (objUnit.content_hash)
		throw Error("trying to get headers size of stripped unit");
	var objHeader = _.cloneDeep(objUnit);
	delete objHeader.unit;
	delete objHeader.headers_commission;
	delete objHeader.payload_commission;
	delete objHeader.oversize_fee;
//	delete objHeader.tps_fee;
	delete objHeader.actual_tps_fee;
	delete objHeader.main_chain_index;
	if (objUnit.version === constants.versionWithoutTimestamp)
		delete objHeader.timestamp;
	delete objHeader.messages;
	delete objHeader.parent_units; // replaced with PARENT_UNITS_SIZE
	var bWithKeys = (objUnit.version !== constants.versionWithoutTimestamp && objUnit.version !== constants.versionWithoutKeySizes);
	return getLength(objHeader, bWithKeys) + PARENT_UNITS_SIZE + (bWithKeys ? PARENT_UNITS_KEY_SIZE : 0);
}
```

**File:** network.js (L1165-1174)
```javascript
	var validate = function(){
		mutex.lock(['handleJoint'], function(unlock){
			if (ws && !conf.bLight)
				currentJointHost = ws.host;
			// clear host only if validation completed with any result, otherwise it crashed and we keep it for a while to avoid DoS from the same peer
			const clearHost = () => {
				if (ws && !conf.bLight)
					currentJointHost = null;
			};
			validation.validate(objJoint, {
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

**File:** mutex.js (L43-59)
```javascript
function exec(arrKeys, proc, next_proc){
	arrLockedKeyArrays.push(arrKeys);
	console.log("lock acquired", arrKeys);
	var bLocked = true;
	proc(function unlock(unlock_msg) {
		if (!bLocked)
			throw Error("double unlock?");
		if (unlock_msg)
			console.log(unlock_msg);
		bLocked = false;
		release(arrKeys);
		console.log("lock released", arrKeys);
		if (next_proc)
			next_proc.apply(next_proc, arguments);
		handleQueue();
	});
}
```

**File:** mutex.js (L75-86)
```javascript
function lock(arrKeys, proc, next_proc){
	if (arguments.length === 1)
		return new Promise(resolve => lock(arrKeys, resolve));
	if (typeof arrKeys === 'string')
		arrKeys = [arrKeys];
	if (isAnyOfKeysLocked(arrKeys)){
		console.log("queuing job held by keys", arrKeys);
		arrQueuedJobs.push({arrKeys: arrKeys, proc: proc, next_proc: next_proc, ts:Date.now()});
	}
	else
		exec(arrKeys, proc, next_proc);
}
```
