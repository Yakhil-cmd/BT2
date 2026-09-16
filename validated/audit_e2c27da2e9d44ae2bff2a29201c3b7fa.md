### Title
Uncaught length-mismatch exception in c-hash validation crashes node on a crafted address string - (File: chash.js)

### Finding Description
The CVE describes a heap-based buffer overflow in `image_buffer_resize` caused by an internal size-tracking bug in `fromsixel.c`: a buffer is resized/allocated based on internally computed dimensions that can go out of sync with the actual data being written, so the write overruns the buffer, causing a crash.

The analogous bug class in `ocore` is a size/length-invariant mismatch in the c-hash decode path in `chash.js`. `isChashValid()` first validates only the *encoded string length* (32 or 48 chars) and wraps only the base32/base64 `decode()` call in a `try/catch`: [1](#0-0) 

But the *decoded byte length* is never validated after decoding. `buffer2bin(chash)` converts whatever byte length `base32.decode()`/`Buffer.from(..., 'base64')` produced into a bit string, and that bit string is passed to `separateIntoCleanDataAndChecksum(binChash)`, which throws a plain, uncaught `Error` if the length isn't exactly 160 or 288 bits: [2](#0-1) 

This throw happens **outside** the `try/catch` in `isChashValid` (lines 163-171), so any encoded string of the correct character-length (32 or 48) that decodes to a byte length other than 20 or 36 bytes propagates an uncaught exception up the call stack. The permissive `thirty-two` base32 decoder does not strictly reject all malformed/padded inputs of a given character count with a consistent output length, so a crafted 32-character string can decode to something other than 20 bytes without `base32.decode()` itself throwing.

`isChashValid` is the sole implementation backing `isValidChash`, which backs `isValidAddress`/`isValidAddressAnyCase`, used pervasively throughout unit/message/definition validation: [3](#0-2) 

`validation.js` calls `isValidAddress` on attacker-supplied fields (author addresses, output addresses, filter addresses, definition addresses, etc.) throughout `validateAuthor`, `validatePaymentInputsAndOutputs`, and `validateDefinition`: [4](#0-3) [5](#0-4) 

None of these call sites wrap `isValidAddress` in `try/catch`. The only global `uncaughtException` handler found in the codebase is in `network.js`, used for network-connection-level exceptions, not for validation-path errors; there is no evidence that unit-validation code guards against a synchronous throw from deep inside the chash length check.

### Impact Explanation
Because `isValidAddress`/`isValidChash` is invoked directly (synchronously, without a wrapping try/catch) from many places in unit/message/definition validation on attacker-controlled address strings, a single malicious unit or AA trigger containing a crafted address (or address-like filter/oracle/attestor field) that passes the length gate but decodes to an unexpected byte count triggers an uncaught `Error` thrown from `separateIntoCleanDataAndChecksum`. In Node.js, an uncaught synchronous exception thrown outside of any try/catch crashes the process. Since this same crafted unit would be broadcast to and independently processed by every full node, this is a deterministic full-node crash triggerable by any unprivileged unit poster — i.e., a network unable to confirm new units once the malicious unit propagates.

### Likelihood Explanation
The bug is reachable purely by constructing a JSON unit with an address (or nested address field inside a definition/filter/oracle list) whose base32-decodable value has the right printable length but an "off" decoded byte length. This does not require any privileged relationship to the network, hub, or other nodes — it only requires posting/broadcasting a unit or having it referenced inside an AA trigger, definition, or filter that other nodes will validate. The exact character sequences needed depend on `thirty-two`'s decoding behavior for malformed/padded base32 input, which was not fully confirmed in this investigation (index does not include the `thirty-two` package source), so likelihood cannot be rated with full certainty without directly testing candidate inputs against `base32.decode`.

### Recommendation
In `chash.js`, validate the *decoded* buffer length immediately after `base32.decode`/`Buffer.from` (must be exactly 20 bytes for 160-bit chash, or 36 bytes for 288-bit chash) and return `false` (not throw) on mismatch, before calling `buffer2bin`/`separateIntoCleanDataAndChecksum`. Additionally, widen the existing `try/catch` in `isChashValid` to cover the entire body (through the final `checksum.equals(...)` call) so any unexpected internal error degrades to `return false` rather than propagating as an uncaught exception into unit-validation call sites.

### Proof of Concept
1. Craft a JSON unit (or AA-trigger/definition/filter field) with an `authors[0].address` (or another field validated via `isValidAddress`) set to a 32-character base32-alphabet string that `thirty-two`'s permissive decoder turns into a byte buffer whose length is not 20 bytes (e.g., a string using non-standard padding/casing accepted by the decoder without error).
2. Broadcast this unit to a full node.
3. `validation.js` calls `isValidAddress(objAuthor.address)` → `chash.isChashValid` → `buffer2bin` → `separateIntoCleanDataAndChecksum`, which throws `Error("bad length=...")` outside any try/catch in the validation call chain.
4. The uncaught exception crashes the node process, and because the same unit is relayed and independently validated by every node in the network, it can be used to disrupt validation/confirmation network-wide.

(Note: exact input strings that reproduce a non-20/36-byte decode from `thirty-two`'s `base32.decode` could not be verified directly in this session because the library's source was not available in the indexed codebase; a Devin session with full filesystem/test access would be needed to confirm concrete PoC strings.)

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

**File:** chash.js (L152-163)
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
```

**File:** validation_utils.js (L52-62)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}

function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}
```

**File:** validation.js (L1149-1177)
```javascript
function validateAuthor(conn, objAuthor, objUnit, objValidationState, callback){
	if (objValidationState.bAA && hasFieldsExcept(objAuthor, ["address"]))
		throw Error("unknown fields in AA author");
	if (!objValidationState.bAA) {
		if (hasFieldsExcept(objAuthor, ["address", "authentifiers", "definition"]))
			return callback("unknown fields in author");
		if (!isNonemptyObject(objAuthor.authentifiers) && !objUnit.content_hash)
			return callback("no authentifiers");
		for (var path in objAuthor.authentifiers) {
			if (!isNonemptyString(objAuthor.authentifiers[path]))
				return callback("authentifiers must be nonempty strings");
			if (objAuthor.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return callback("authentifier too long");
		}
	}
	
	var bNonserial = false;
	var bInitialDefinition = false;

	if (objValidationState.bAA) {
		storage.readAADefinition(conn, objAuthor.address, objValidationState.aa_mci, function (arrDefinition) {
			if (!arrDefinition)
				throw Error("AA definition not found " + objAuthor.address);
			checkSerialAddressUse();
		});
		return;
	}
	
	var arrAddressDefinition = objAuthor.definition;
```

**File:** validation.js (L2151-2186)
```javascript
	for (var i=0; i<payload.outputs.length; i++){
		var output = payload.outputs[i];
		if (!isNonemptyObject(output))
			return callback("output must be a non-empty object");
		if (hasFieldsExcept(output, ["address", "amount", "blinding", "output_hash"]))
			return callback("unknown fields in payment output");
		if (!isPositiveInteger(output.amount))
			return callback("amount must be positive integer, found "+JSON.stringify(output.amount));
		if (output.amount > constants.MAX_CAP)
			return callback("output too large: " + output.amount);
		if (objAsset && objAsset.fixed_denominations && output.amount % denomination !== 0)
			return callback("output amount must be divisible by denomination");
		if (objAsset && objAsset.is_private){
			if (("output_hash" in output) !== !!objAsset.fixed_denominations)
				return callback("output_hash must be present with fixed denominations only");
			if ("output_hash" in output && !isStringOfLength(output.output_hash, constants.HASH_LENGTH))
				return callback("invalid output hash");
			if (!objAsset.fixed_denominations && !(("blinding" in output) && ("address" in output)))
				return callback("no blinding or address");
			if ("blinding" in output && !isStringOfLength(output.blinding, 16))
				return callback("bad blinding");
			if (("blinding" in output) !== ("address" in output))
				return callback("address and blinding must come together");
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
			if (prev_address > output.address)
```
