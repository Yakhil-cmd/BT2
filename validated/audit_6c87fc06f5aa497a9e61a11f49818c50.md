Confirmed: there is a global `process.on('uncaughtException', ...)` handler in `network.js` that explicitly re-throws to **crash the whole process** whenever any exception escapes normal handling [1](#0-0) . This means any uncaught exception thrown deep inside the synchronous validation path for a maliciously crafted, network-reachable unit will bring the node down.

### Title
Uncaught exception in c-hash decoding on malformed address/asset strings crashes the node - (File: chash.js)

### Summary
`chash.isChashValid()`, reachable indirectly by any field validated with `isValidAddress`/`isValidChash` (author addresses, output addresses, definition-chash, asset/device addresses, etc.), decodes an attacker-supplied base32/base64 string and feeds the decoded bytes into `separateIntoCleanDataAndChecksum()` without a surrounding try/catch, allowing a single malformed-but-correct-length string to throw an unhandled exception that crashes the process via the global `uncaughtException` handler.

### Finding Description
The CVE describes stb_vorbis trusting internal length/size fields derived from attacker input without validating them against the actual decoded buffer, leading to memory corruption when decoding a malicious file. The closest reachable analog in this pure-JS codebase is a class of bugs where a length invariant assumed by decoding code is not actually guaranteed by the earlier length check, and the mismatch is not caught, producing an unhandled exception instead of memory corruption (JS has no raw memory to corrupt, but the "unvalidated internal length -> broken decode path -> crash" pattern is the same).

`isValidChash(str, len)` gates on `isStringOfLength(str, len)` (encoded string length 32 or 48) [2](#0-1) . Inside `chash.isChashValid`, the *encoded* string length is re-checked (32 or 48), then decoded:

```
var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
``` [3](#0-2) 

This decode is wrapped in try/catch, but the *subsequent* call is not:
```
var binChash = buffer2bin(chash);
var separated = separateIntoCleanDataAndChecksum(binChash);
``` [4](#0-3) 

`separateIntoCleanDataAndChecksum` assumes `bin.length` (i.e. `chash.length*8`) is exactly 160 or 288 bits, and `throw`s an `Error` otherwise [5](#0-4) . The 32/48-character *encoded* length does not strictly guarantee a fixed *decoded* byte length: `Buffer.from(str, 'base64')` in Node.js silently skips invalid/out-of-alphabet characters rather than throwing, so a 48-character string containing characters outside the base64 alphabet (or unusual padding) can decode to a buffer whose length is not 36 bytes (288 bits), and `thirty-two`'s `base32.decode` has similar leniency for malformed input of the nominal 32-character length. This causes `separateIntoCleanDataAndChecksum` to throw, uncaught, all the way up through `isChashValid` → `isValidChash` → `isValidAddress`/`isValidChash` used throughout unit/message/definition validation in `validation.js`, `definition.js`, `formula/evaluation.js`, etc.

Because unit validation runs synchronously inside `validation.validate()` invoked from `network.handleJoint`/`handleOnlineJoint`, an uncaught throw there propagates to Node's `uncaughtException` handler in `network.js`, which deliberately re-throws to crash the process [1](#0-0) .

### Impact Explanation
A single attacker-crafted unit (or AA trigger/definition field) containing a malformed but correctly-*sized* address/chash-like string can crash any full node, light node, hub, or relay that validates it. If broadcast to the network, every node that processes the malicious unit before rejecting bad peers can crash simultaneously, disrupting the network's ability to confirm new units — matching the "network unable to confirm new units" acceptance criterion.

### Likelihood Explanation
Reaching this path requires only posting/broadcasting a unit whose address-like/chash-like field has the exact required string length (32 or 48 chars) but decodes (via lenient base32/base64 decoding) to a byte length other than 20/36 bytes. This is a low-effort, unprivileged, single-message attack (no valid signature needed if the field is checked before signature/authentifier validation, and even if checked after, an attacker's own signed unit suffices).

### Recommendation
Wrap the `buffer2bin`/`separateIntoCleanDataAndChecksum` calls inside `isChashValid` in try/catch and return `false` on any exception (matching the existing pattern already used around the decode step), and/or explicitly verify `chash.length` equals the expected byte length (20 or 36) immediately after decoding, before calling `separateIntoCleanDataAndChecksum`.

### Proof of Concept
```js
var chash = require('./chash.js');
// 48-char string with invalid base64 alphabet characters so that
// Buffer.from(str,'base64') silently produces a buffer whose length != 36 bytes
var malformed = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"; // len 48, all invalid base64 chars -> decodes to 0-length buffer
console.log(chash.isChashValid(malformed)); // throws instead of returning false, crashing any process without a surrounding try/catch (e.g. via handleJoint -> uncaughtException handler)
```
Feeding such a string as, e.g., an `asset` field, `definition` address, or any field validated through `isValidAddress`/`isValidChash` in a broadcast unit reaches this code path during `validation.validate()` and crashes the node process.

### Citations

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

**File:** validation_utils.js (L48-54)
```javascript
function isStringOfLength(str, len){
	return (typeof str === "string" && str.length === len);
}

function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}
```

**File:** chash.js (L45-53)
```javascript
function separateIntoCleanDataAndChecksum(bin){
	var len = bin.length;
	var arrOffsets;
	if (len === 160)
		arrOffsets = arrOffsets160;
	else if (len === 288)
		arrOffsets = arrOffsets288;
	else
		throw Error("bad length="+len+", bin = "+bin);
```

**File:** chash.js (L152-164)
```javascript
function isChashValid(encoded){
	var encoded_len = encoded.length;
	if (encoded_len !== 32 && encoded_len !== 48) // 160/5 = 32, 288/6 = 48
		throw Error("wrong encoded length: "+encoded_len);
	try{
		var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
	}
	catch(e){
		console.log(e);
		return false;
	}
	var binChash = buffer2bin(chash);
	var separated = separateIntoCleanDataAndChecksum(binChash);
```
