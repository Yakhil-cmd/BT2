### Title
Unhandled exception in c-hash / address validation via malformed base32 decoding - (File: chash.js)

### Summary
`chash.js`'s `isChashValid()` function decodes an address string and passes the decoded bytes through several length-sensitive parsing steps (`buffer2bin`, `separateIntoCleanDataAndChecksum`, `bin2buffer`) that `throw` on any length mismatch, but only the initial `base32.decode`/`Buffer.from` call is wrapped in a `try/catch`. Because address strings are attacker-controlled data present in virtually every unit (author addresses, output addresses, definition addresses, AA trigger fields, attestation targets, asset issuer/attestor addresses), a value that passes the shallow length check at the call site but decodes to an unexpected number of bits can reach the unguarded `separateIntoCleanDataAndChecksum()` and throw an uncaught `Error`, mirroring the CVE-2016-3186 pattern of insufficiently bounds-checked parsing of externally supplied, length-governed data leading to a crash.

### Finding Description
`chash.js` computes and validates "c-hashes" (the encoding used for ocore addresses): [1](#0-0) 

`isChashValid()` decodes the base32/base64-encoded address into a buffer, but the `try/catch` only guards the decode call itself:
```
try{ var chash = ...decode... } catch(e){ ... return false; }
var binChash = buffer2bin(chash);
var separated = separateIntoCleanDataAndChecksum(binChash);   // <-- unguarded
var clean_data = bin2buffer(separated.clean_data);
var checksum = bin2buffer(separated.checksum);
```

`separateIntoCleanDataAndChecksum()` explicitly `throw`s when the decoded bit-length isn't exactly 160 or 288: [2](#0-1) 

This function is invoked by `validation_utils.js`'s `isValidAddress()` (used pervasively across `validation.js`, `definition.js`, AA definition/trigger validation, private-payment chain validation, and device/wallet address checks) to accept or reject any address supplied inside a posted unit, an AA definition, an AA trigger, or a private-payment chain. Any code path in which the outer length gate (a fixed 32/48-character string check) does not perfectly guarantee that the underlying decode always yields exactly 160/288 bits (e.g. non-canonical base32 padding, decoder quirks, or any future change to the surrounding character-length check) causes `isChashValid()` to throw synchronously and uncaught out of the address-validation call stack.

This is the same bug class as CVE-2016-3186: a parsing routine that decodes length-governed, attacker-supplied data and only partially validates lengths before indexing/using that data, allowing a crafted input to crash the process instead of being cleanly rejected.

### Impact Explanation
If the uncaught exception propagates out of unit/AA/definition validation, it is not caught by the node's normal per-unit error handling and results in an uncaught exception. In this codebase, uncaught exceptions in the main process are deliberately re-thrown to crash the process: [3](#0-2) 

Because address strings appear in every unit an unprivileged poster can construct (author addresses, definition addresses, AA trigger fields, attestation payloads, private-payment chains), a single crafted unit/message containing a malformed address could crash every full node that attempts to validate it — a network-wide denial of service preventing new units from being confirmed, which matches the "network unable to confirm new units" impact bar in the validation rules.

### Likelihood Explanation
Reaching `isChashValid()` requires only posting a unit, AA trigger, or private-payment chain containing an address field — something any unprivileged actor can do. The likelihood that a value can pass the length gate at the call site (e.g., `isStringOfLength(address, 32)`) yet decode via `base32`/`Buffer.from` to bit-length other than 160/288 depends on decoder edge-case behavior (case normalization, non-canonical padding characters) that could not be fully confirmed from the indexed code alone; this is the main open uncertainty in this analog and should be verified directly against the `thirty-two` decoder's behavior for 32-character inputs.

### Recommendation
Wrap the entire body of `isChashValid()` — not just the initial decode — in the existing `try/catch`, so that any length-mismatch `Error` thrown by `separateIntoCleanDataAndChecksum()`/`bin2buffer()` results in `return false` instead of propagating as an uncaught exception. Additionally, add an explicit length assertion immediately after decoding (before calling `buffer2bin`) so malformed/atypical decodings are rejected deterministically rather than relying on downstream code to throw safely.

### Proof of Concept
Conceptual PoC (pending confirmation of a base32 input that satisfies the 32-character gate in `isValidAddress` while decoding to a bit-length ≠ 160):
1. Construct an address string of the expected character length but using non-canonical base32 characters/padding such that `base32.decode()` (from the `thirty-two` package) yields a buffer whose length in bits is not exactly 160.
2. Include this address as a unit author address, output address, or AA-trigger data field and post it to the network.
3. `isValidAddress()` → `chash.isChashValid()` → `separateIntoCleanDataAndChecksum()` throws `Error("bad length=...")` outside the `try/catch`, propagating as an uncaught exception during unit validation and crashing the validating node via the global `uncaughtException` handler in `network.js`.

Because the exact decoder edge case that would produce a bit-length mismatch under the 32-character length gate could not be verified from the indexed source alone, this PoC step should be validated against the live `thirty-two` base32 implementation before treating this as a confirmed exploit.

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
