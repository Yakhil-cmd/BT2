### Title
Unhandled exception (node crash) via malformed c-hash decoding of an attacker-controlled address string - (File: `chash.js`)

### Summary
`chash.js`'s `isChashValid()` only wraps the initial `base32.decode()`/`Buffer.from()` call in a `try/catch`. The subsequent length-dependent processing (`buffer2bin`, `separateIntoCleanDataAndChecksum`, `bin2buffer`) is executed outside that `try/catch` and throws a plain, uncaught `Error` whenever the decoded byte length doesn't match the expected 160/288-bit checksum layout. This mirrors the reported bug class in `onos-lib-go` (`GHSA-jrqj-6vq2-7r63`): a derived/decoded length value (there, `numBits`; here, the byte length coming out of `base32.decode`) is used to index/slice a buffer without validating that it matches the length the rest of the function assumes, causing an out-of-range/length-mismatch panic.

### Finding Description
`isChashValid(encoded)` in `chash.js` is the single implementation backing `ValidationUtils.isValidChash` → `isValidAddress`/`isValidAddressAnyCase`, which is used pervasively to validate any base32/base64-encoded address string received from the network (unit authors, definitions, AA triggers, payment output addresses, signed messages, shared-address setup, etc.): [1](#0-0) 

Inside `isChashValid`: [2](#0-1) 

Only the decode step (`base32.decode(encoded)` or `Buffer.from(encoded, 'base64')`) is protected by `try/catch`. The immediately following calls are not:
- `buffer2bin(chash)` converts the decoded buffer to a bit-string based on `chash.length`.
- `separateIntoCleanDataAndChecksum(binChash)` throws a raw `Error("bad length=...")` if the bit-string length is not exactly 160 or 288: [3](#0-2) 

`encoded_len` (the *string* length, checked to be 32 or 48) does not guarantee that the *decoded byte length* will be 20 or 36 bytes respectively. The `thirty-two` base32 library (and to a lesser extent `Buffer.from(..., 'base64')`) can decode strings containing unexpected characters or padding into a buffer of a different length than the "clean" case, because `isValidAddress` performs its own separate regex check (`/^[A-Z2-7]{32}\$/`) only for the "canonical" address path, while `isValidAddressAnyCase` (used for e.g. `is_valid_address`/attestor/oracle address checks, seen-address checks, and various message fields) calls `isValidChash` directly without that regex, allowing characters/padding combinations that decode to a non-20-byte buffer to reach `isChashValid` unguarded: [4](#0-3) 

When that happens, `separateIntoCleanDataAndChecksum` throws outside of any `try/catch`, propagating as an unhandled exception up through `isValidChash` → callers such as `definition.js` validation (`'seen address'`, `'attested'`, `'address'` op handling), `formula/evaluation.js`'s `is_valid_address`/`is_aa` oscript functions evaluated from AA triggers, and other validation call sites that do not themselves wrap the address check in `try/catch`.

### Impact Explanation
An unhandled JavaScript exception thrown synchronously during unit/AA-trigger/definition/message validation crashes the Node.js process (uncaught exception terminates the process unless a global handler exists), i.e. a full-node/AA-witness denial of service. Because address validation is invoked from many single-message-triggered validation paths (a posted unit's `'seen address'`/`'attested'` definition ops, an AA trigger's oscript `is_valid_address`/`is_aa` calls, wallet/device-message address checks), a single crafted unit, AA trigger payload, or device/wallet message containing a malformed address-like string can crash the receiving node, matching the "network unable to confirm new units" / node-disagreement class of impact this scan targets (a crashed node stops validating and stops confirming units until restarted).

### Likelihood Explanation
Likelihood depends on whether an attacker can actually construct an encoded string of the correct string length (32 or 48 chars) that decodes via `thirty-two`'s `base32.decode` (or `Buffer.from(..., 'base64')`) to a byte buffer of unexpected length. This requires either: (a) reaching `isChashValid` through `isValidAddressAnyCase`/`isValidChash` (which skips the strict `A-Z2-7` regex enforced by `isValidAddress`), and (b) crafting base32/base64 input whose decoded length diverges from the canonical 20/36 bytes (e.g., through padding characters, lowercase, or other characters the decoder tolerates). This is plausible but unverified against the exact behavior of the bundled `thirty-two` decoder — I was not able to inspect its decode implementation directly in this session to confirm which character classes silently yield a shorter/longer buffer versus which throw. This uncertainty should be resolved by directly testing `require('thirty-two').decode()` with malformed padding/characters to confirm a length-mismatch (rather than a caught exception) is achievable in practice.

### Recommendation
- Wrap the entire body of `isChashValid` (not just the initial decode call) in a single `try/catch` returning `false` on any error, exactly as is already done for the `base32.decode`/`Buffer.from` call, and as several existing production call sites (`aa_addresses.js`, `wallet_defined_by_addresses.js`, `definition.js`) already defensively do around other chash/hash calls.
- Additionally/alternatively, explicitly validate `chash.length === 20` (for the 160-bit path) or `chash.length === 36` (for the 288-bit path) immediately after decoding, before calling `buffer2bin`, and return `false` if the decoded length doesn't match.
- Audit all direct/indirect callers of `isChashValid`/`isValidChash`/`isValidAddressAnyCase` to ensure none of them assume this function can never throw.

### Proof of Concept
Conceptual PoC (exact malicious encoded string depends on `thirty-two`'s decode behavior, which needs to be verified in a live environment/session):
```js
const chash = require('./chash.js');
// A 32-character string that passes encoded_len checks but, once decoded,
// yields a buffer whose bit-length is not 160, triggering the uncaught
// "bad length=..." Error inside separateIntoCleanDataAndChecksum,
// which is NOT caught by the try/catch in isChashValid.
chash.isChashValid('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='); // example padding-laden input
```
Reaching this from an unprivileged path, e.g. via an AA trigger formula using `is_valid_address(trigger.data.addr)` where `trigger.data.addr` is attacker-controlled, or via a unit's `'seen address'`/`'attested'` definition referencing a crafted address string, would propagate the uncaught exception into the node's validation pipeline.

**Note on confidence:** This analog is plausible and structurally matches the reported bug class (unchecked derived-length causing an out-of-range/length-mismatch panic in a low-level decode routine), and the missing `try/catch` scope is directly verifiable in the code. However, I could not confirm within this session whether the bundled `thirty-two` base32 decoder can actually be coerced into producing a length-mismatched buffer for a 32-character input (versus throwing inside the already-caught block, or always producing exactly 20 bytes for any 32-char input it accepts). Starting a Devin session with terminal access to fuzz `thirty-two`'s decoder against `isChashValid` would be needed to fully confirm exploitability before treating this as a fully proven finding.

### Citations

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
