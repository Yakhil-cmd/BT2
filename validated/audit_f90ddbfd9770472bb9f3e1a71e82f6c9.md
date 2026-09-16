### Title
Uncaught length-mismatch exception in `chash.isChashValid` reachable via `isValidAddressAnyCase` on legacy units - ([File: chash.js])

### Summary
`chash.js`'s `isChashValid` only length-checks the *encoded* string (32 or 48 chars) before calling `base32.decode()`/`Buffer.from(..., 'base64')`, then unconditionally feeds the decoded bytes into `buffer2bin()` → `separateIntoCleanDataAndChecksum()`, which `throw`s if the resulting bit-length isn't exactly 160 or 288. This mirrors the libidn CVE pattern (a decoder that assumes a fixed input geometry and reads/derives data past what it validated, crashing on out-of-range input). In ocore, the crash path is reachable without the strict `A-Z2-7` charset check because `isValidAddressAnyCase` (used for pre-`timestampUpgradeMci` unit validation) only checks string length via `isStringOfLength`, not the regex that `isValidAddress` enforces.

### Finding Description
`isChashValid` in [1](#0-0)  does:
```
var encoded_len = encoded.length;
if (encoded_len !== 32 && encoded_len !== 48)
    throw Error(...);
try{
    var chash = (encoded_len === 32) ? base32.decode(encoded) : Buffer.from(encoded, 'base64');
}
catch(e){ return false; }
var binChash = buffer2bin(chash);
var separated = separateIntoCleanDataAndChecksum(binChash);   // <-- can throw uncaught
```
Only the `base32.decode`/`Buffer.from` call is wrapped in try/catch. If the decoded buffer does not end up being exactly 20 bytes (160 bits) or 36 bytes (288 bits) — e.g., because the base32 string contains characters/padding that `thirty-two`'s decoder tolerates but that don't map to a clean 160-bit payload — `separateIntoCleanDataAndChecksum` throws `Error("bad length=" + len + ...)` [2](#0-1) , which is **not caught** by `isChashValid`.

This function is reached from `isValidChash`/`isValidAddressAnyCase` in [3](#0-2) . Critically, `isValidAddress` first enforces `/^[A-Z2-7]{32}$/` before calling `isValidChash` [4](#0-3) , but `isValidAddressAnyCase` does **not** apply this charset filter — it only checks `isStringOfLength(address, 32)` [5](#0-4) .

`isValidAddressAnyCase` is selected as the active address validator for units whose `last_ball_mci` is below `constants.timestampUpgradeMci`, via `isValidAddressWithCase` inside `validatePaymentInputsAndOutputs`:
```
const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci
    ? ValidationUtils.isValidAddress
    : ValidationUtils.isValidAddressAnyCase;
``` [6](#0-5)  This is then used to validate every payment output address [7](#0-6) . An attacker posting a unit whose `last_ball_mci` still falls under the pre-upgrade path can therefore submit a 32-character output address containing arbitrary bytes/characters outside `A-Z2-7` (e.g. lowercase, punctuation, or non-canonical base32 that the `thirty-two` decoder still parses but which decodes to a buffer length other than 20 bytes), driving execution into the unguarded `throw` inside `separateIntoCleanDataAndChecksum`.

### Impact Explanation
An uncaught synchronous `Error` thrown deep inside unit validation (payment output validation, reachable from any node processing/relaying an untrusted unit) is a crash primitive analogous to the libidn OOB-read crash: a single malicious unit can throw an unhandled exception during validation of a broadcast/joint. Depending on how far up the call stack the exception propagates without a catch, this can abort processing of the unit (denial-of-service on that node's validation pipeline) or, if it escapes async callbacks entirely, crash the Node.js process — a node unable to confirm new units, satisfying the required "network unable to confirm new units" impact class for nodes still operating below `timestampUpgradeMci` semantics (relevant for older/testnet/light logic paths still executing this branch).

### Likelihood Explanation
Reachability requires only posting a unit with a payment output address of exactly 32 characters that is not a valid canonical `A-Z2-7` chash but decodes (via `thirty-two`) to a buffer whose bit-length ≠ 160. This depends on the tolerance of the `thirty-two` base32 decoder for non-canonical alphabets/padding, which was not directly verifiable in the indexed codebase (the `thirty-two` package itself is a dependency and its exact decode behavior for out-of-alphabet or malformed strings could not be inspected here). Because the confirmed mitigating check (`isValidAddress`'s regex) is bypassed only on the `isValidAddressAnyCase` branch, exploitability is conditional on that legacy code path still being reachable in current network state (i.e., mci below `timestampUpgradeMci`), which lowers confidence for an up-to-date mainnet but could still be relevant to relayed/replayed old units, light clients, or alternate networks that haven't crossed that mci.

### Recommendation
Wrap the entire body of `isChashValid` (including `buffer2bin` and `separateIntoCleanDataAndChecksum`) in the existing try/catch rather than only the decode call, and return `false` on any thrown error instead of throwing. Additionally, consider validating decoded byte-length explicitly (`chash.length === 20` or `36`) before proceeding, and align `isValidAddressAnyCase` to enforce a base32 charset check to avoid relying solely on decoder tolerance.

### Proof of Concept
Not fully verifiable without directly exercising the `thirty-two` decoder's behavior on non-canonical input, since that dependency's source was not available in the index. Conceptually: call `chash.isChashValid("<32-char string outside A-Z2-7 alphabet that thirty-two still decodes to a non-20-byte buffer>")` and observe the uncaught `Error("bad length=...")` from `separateIntoCleanDataAndChecksum`, then trigger the same address through a unit's payment output while `last_ball_mci < constants.timestampUpgradeMci` so that `isValidAddressAnyCase` is used in `validatePaymentInputsAndOutputs`.

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

**File:** validation_utils.js (L52-58)
```javascript
function isValidChash(str, len){
	return (isStringOfLength(str, len) && chash.isChashValid(str));
}

function isValidAddressAnyCase(address){
	return isValidChash(address, 32);
}
```

**File:** validation_utils.js (L60-62)
```javascript
function isValidAddress(address){
	return (typeof address === "string" && /^[A-Z2-7]{32}$/.test(address) && isValidChash(address, 32));
}
```

**File:** validation.js (L2145-2145)
```javascript
	const isValidAddressWithCase = objValidationState.last_ball_mci >= constants.timestampUpgradeMci ? ValidationUtils.isValidAddress : ValidationUtils.isValidAddressAnyCase;
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
