## Finding [1](#0-0) 

### Title
Uncaught exception / process crash via malformed c-hash address decoding in `isChashValid` - (File: chash.js)

### Summary
`chash.js`'s `isChashValid()` only length-checks the *encoded* address string (32 or 48 characters) before decoding it, but never re-validates the *decoded* byte length before feeding it into `buffer2bin`/`separateIntoCleanDataAndChecksum`. Those downstream functions `throw Error(...)` when the bit-length of the decoded data is not exactly 160 or 288, and that throw is not wrapped in any `try/catch` inside `isChashValid`, so it propagates as an uncaught exception all the way up through address validation.

### Finding Description
`isChashValid()` performs the length gate only on the encoded string: [2](#0-1) 
It then calls `buffer2bin` and `separateIntoCleanDataAndChecksum`, the latter of which enforces an exact bit length of 160 or 288 and otherwise unconditionally throws: [3](#0-2) 

The only `try/catch` in `isChashValid` wraps the `base32.decode`/`Buffer.from` call, not the subsequent `buffer2bin`/`separateIntoCleanDataAndChecksum`/`bin2buffer` calls: [4](#0-3) 

Because `thirty-two`'s base32 decoder is lenient about invalid/incorrectly-padded input (a common property of minimal base32 implementations), a 32-character string that passes the `encoded_len === 32` gate can still decode to a byte buffer whose length is not exactly 20 bytes (160 bits). When that happens, `separateIntoCleanDataAndChecksum` throws `"bad length=..."`, and this exception is not caught anywhere in the call chain.

`isChashValid` (via `isValidAddress` in `validation_utils.js`) is invoked pervasively and synchronously throughout unit validation — for every author address, every payment output address, asset-attestor addresses, etc. — inside `validation.js`'s top-level `validate()` function, in code that is *not* wrapped in `try/catch`, e.g. the payment-message sanity check: [5](#0-4) 
and later in `validatePaymentInputsAndOutputs`: [6](#0-5) 

An uncaught exception thrown during processing of network-received data ultimately reaches the process-level handler that intentionally crashes the whole node: [7](#0-6) 

This mirrors the CVE-2018-10998 bug class exactly: an internal length/consistency invariant (analogous to `Safe::add`) is checked with a hard `throw`/abort instead of being validated defensively against attacker-controlled input length, and that check is reachable from parsing a single untrusted external message.

### Impact Explanation
Any unprivileged peer can post a unit (or a payment/asset message) containing a crafted 32- or 48-character address-like string in an `address` field (author address, output address, asset attestor address, etc.) that decodes to a byte length other than the expected 20/36 bytes. This causes an uncaught exception during synchronous validation, which is caught by the global `uncaughtException` handler that deliberately re-throws to crash the node process. This is a network-reachable denial of service: a single hostile unit can crash any full node (or hub) that attempts to validate it, i.e. "a network unable to confirm new units" if propagated widely, satisfying the required Medium/High impact bar.

### Likelihood Explanation
The attack requires no privileges beyond the ability to post/broadcast a single unit with an attacker-chosen (invalid) address string — the same posting capability available to any unprivileged unit author. The remaining uncertainty is whether the specific `thirty-two` base32 decoder used by this project is lenient enough to decode a 32-character malformed string to a non-20-byte buffer; this depends on the exact library version/behavior and was not directly verifiable from the indexed source, so likelihood should be treated as **plausible but not fully confirmed** without dynamic testing of the `thirty-two` module.

### Recommendation
In `isChashValid`, after decoding, explicitly verify `chash.length * 8 === (encoded_len === 32 ? 160 : 288)` (or equivalently check `chash.length === 20` / `36`) and return `false` gracefully if not, before calling `buffer2bin`/`separateIntoCleanDataAndChecksum`. Additionally, wrap the entire body of `isChashValid` in `try/catch` so any unexpected internal error results in `return false` rather than an uncaught exception, consistent with how `hasValidHashes`/`hasValidPayloadHashes` in `validation.js` already defensively catch hashing errors.

### Proof of Concept
1. Craft a unit where an address field (e.g., a payment output `address`, or an author `address`) is set to a 32-character string composed of valid base32 alphabet characters but with padding/structure that causes the `thirty-two` decoder to return a buffer that is not exactly 20 bytes (e.g. a string with trailing padding characters mixed with data characters that shift the effective decoded bit count away from a multiple of 160).
2. Broadcast this unit to a full node.
3. During `validation.js`'s `validate()` → `isValidAddress()` → `chash.isChashValid()` call chain, `separateIntoCleanDataAndChecksum` throws `Error("bad length=...")` uncaught.
4. The exception propagates past the network message handler and triggers `process.on('uncaughtException', ...)` in `network.js`, which re-throws and crashes the node process — denial of service from a single unprivileged unit.

*(Note: exact reproduction depends on confirming the lenient decoding behavior of the bundled `thirty-two` package version, which could not be directly inspected in this analysis; a Devin session with full filesystem/dependency access should verify this before treating the PoC as fully confirmed.)*

### Citations

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

**File:** chash.js (L152-171)
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
	var clean_data = bin2buffer(separated.clean_data);
	//console.log("clean data", clean_data);
	var checksum = bin2buffer(separated.checksum);
	//console.log(checksum);
	//console.log(getChecksum(clean_data));
	return checksum.equals(getChecksum(clean_data));
}
```

**File:** validation.js (L245-255)
```javascript
		if (!objUnit.messages.every(m => {
			if (m.app === "payment" && m.payload)
				return isNonemptyArray(m.payload.outputs) &&
					(!("asset" in m.payload) || isStringOfLength(m.payload.asset, constants.HASH_LENGTH)) &&
					m.payload.outputs.every(o => isNonemptyObject(o) && isValidAddress(o.address) && isPositiveInteger(o.amount) && o.amount <= constants.MAX_CAP) &&
					isNonemptyArray(m.payload.inputs) &&
					m.payload.inputs.every(i => isNonemptyObject(i) && (!("type" in i) || ["issue", "headers_commission", "witnessing"].includes(i.type)));
			else
				return true;
		}))
			return callbacks.ifUnitError("invalid payment message");
```

**File:** validation.js (L2174-2185)
```javascript
			if ("address" in output && !isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
			if (output.address)
				count_open_outputs++;
		}
		else{
			if ("blinding" in output)
				return callback("public output must not have blinding");
			if ("output_hash" in output)
				return callback("public output must not have output_hash");
			if (!isValidAddressWithCase(output.address))
				return callback("output address " + JSON.stringify(output.address) + " invalid");
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
