### Title
Crafted DER Signature/PEM Key in `is_valid_sig`/`vrf_verify` Reaches Native secp256k1 Parsing Without JS-Catchable Safety - (File: signature.js)

### Summary
The oscript functions `is_valid_sig` and `vrf_verify`, callable by any AA trigger sender, pass attacker-fully-controlled binary blobs (a PEM-encoded public key and a signature string) into `signature.validateAndFormatPemPubKey()` and `signature.verifyMessageWithPemPubKey()` / `verifyMessageWithSecp256k1PemPubKey()`, which ultimately hand raw, attacker-chosen DER bytes to the native `secp256k1` binding's `ecdsa.signatureImport()` and `ecdsa.ecdsaVerify()` routines [1](#0-0) [2](#0-1) . This is the same bug class as CVE-2018-11382: a parser that walks a crafted binary structure (there, radare2's instruction table; here, a DER-encoded ECDSA signature/public key) without the calling layer being able to guarantee memory-safe bounds handling in the underlying native code.

### Finding Description
`is_valid_sig(message, pem_key, sig)` and `vrf_verify(seed, proof, pem_key)` are oscript/AA formula operators reachable from any unit's trigger data — no privilege beyond posting a normal AA-triggering unit is required [1](#0-0) . The `pem_key` and `sig`/`proof` values come directly from `trigger.data`, fully attacker-controlled strings, validated only for length and character set (hex/base64), not structural correctness [3](#0-2) .

`validateAndFormatPemPubKey()` parses the DER byte-by-byte using raw index access (`contentAloneBuffer[1]`, `[2]`, `[3]`...) to determine ASN.1 length-tag encoding and identifier offsets [4](#0-3) . JS buffer indexing is itself safe (returns `undefined` rather than throwing), but once the key is classified as secp256k1 and passed to `verifyMessageWithSecp256k1PemPubKey()`, the code locates a BIT STRING marker via `der.indexOf(...)`, slices out a 65-byte "public key," and feeds attacker-influenced `sigBytes` into `ecdsa.signatureImport()` and `ecdsa.ecdsaVerify()` from the `secp256k1` npm package [5](#0-4) . These are backed by native/WASM code (libsecp256k1 bindings), and the whole block is wrapped only in a JS `try/catch` [6](#0-5) . A JS `try/catch` can only catch JS-level exceptions; it cannot protect against a memory-safety defect (heap OOB read, buffer overrun) inside the native DER/signature parsing itself, which is analogous to the radare2 `_inst__sts()` OOB bug reached through malformed binary instruction data.

### Impact Explanation
If the native `secp256k1` DER/signature import path has (or develops) any bounds-checking gap on malformed attacker-supplied byte sequences, a single AA trigger from any unprivileged sender could crash the Node.js process evaluating the AA (denial of service), since the failure occurs below the JS exception boundary and is unrecoverable by the surrounding `try/catch`. Because AA evaluation happens on every full node processing that trigger, this could stall confirmation of the affected AA and potentially the node's ability to keep processing the DAG, which matches the "network unable to confirm new units" impact class.

### Likelihood Explanation
Reachability is high: `is_valid_sig`/`vrf_verify` are ordinary formula operators usable in any AA definition, and triggering them requires only posting a normal unit with attacker-chosen `pem_key`/`sig` data — no elevated privilege, asset issuance rights, or witness/hub role needed [7](#0-6) . Exploitability, however, depends on whether the specific native `secp256k1` binding version in use actually contains an unguarded memory-safety bug in its DER-import/verify path — this is a native-dependency question that could not be confirmed from the indexed JS sources alone (the `secp256k1` package internals are not part of this repo's indexed content).

### Recommendation
- Perform strict, self-contained JS-level DER structural validation of `sig`/`proof` (length, tag/length consistency, no trailing garbage) before handing bytes to `ecdsa.signatureImport`/`ecdsa.ecdsaVerify`, rejecting anything that doesn't conform to a minimal, well-formed ECDSA-DER grammar.
- Pin and audit the exact `secp256k1` dependency version for known native memory-safety advisories, and prefer a pure-JS/WASM constant-inspected implementation for untrusted input paths if available.
- Add a supervisor-level restart/isolation strategy (e.g., worker threads/sandboxing) around native crypto verification triggered by untrusted AA data, so a native crash cannot take down the entire node process.

### Proof of Concept
1. Deploy (or use) an AA whose bound expression evaluates `is_valid_sig(trigger.data.message, trigger.data.pem_key, trigger.data.signature)` (a supported and tested pattern, see `test/pem_sig.test.js`) [8](#0-7) .
2. Craft a `trigger.data.pem_key` that is a well-formed secp256k1 SubjectPublicKeyInfo DER (so it passes `validateAndFormatPemPubKey` checks) and a `trigger.data.signature` that is a malformed/edge-case DER ECDSA signature designed to probe boundary conditions in `ecdsa.signatureImport`.
3. Post a unit triggering the AA with this data as any unprivileged user.
4. Observe whether the native `secp256k1` binding mis-handles the malformed signature bytes in a way that a JS `try/catch` cannot intercept (this final native-level verification step could not be executed/confirmed against the actual compiled `secp256k1` dependency from the indexed source alone).

### Citations

**File:** formula/evaluation.js (L1704-1734)
```javascript
			case 'is_valid_sig':
				var message = arr[1];
				var pem_key = arr[2];
				var sig = arr[3];
				evaluate(message, function (evaluated_message) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isNonemptyString(evaluated_message))
						return setFatalError("bad message string in is_valid_sig", { arr }, false, cb);
					evaluate(sig, function (evaluated_signature) {
						if (fatal_error)
							return cb(false);
						if (!ValidationUtils.isNonemptyString(evaluated_signature))
							return setFatalError("bad signature string in is_valid_sig", { arr }, false, cb);
						if (evaluated_signature.length > 1024)
							return setFatalError("signature is too large", { arr }, false, cb);
						if (!ValidationUtils.isValidHexadecimal(evaluated_signature) && !ValidationUtils.isValidBase64(evaluated_signature))
							return setFatalError("bad signature string in is_valid_sig", { arr }, false, cb);
						evaluate(pem_key, function (evaluated_pem_key) {
							if (fatal_error)
								return cb(false);
							signature.validateAndFormatPemPubKey(evaluated_pem_key, "any", function (error, formatted_pem_key){
								if (error)
									return setFatalError("bad PEM key in is_valid_sig: " + error, { arr }, false, cb);
								var result = signature.verifyMessageWithPemPubKey(evaluated_message, evaluated_signature, formatted_pem_key, bPostPemCurvesFix);
								return cb(result);
							}, bPostPemCurvesFix);
						});
					});
				});
				break;
```

**File:** signature.js (L50-69)
```javascript
function verifyMessageWithSecp256k1PemPubKey(message, signature, der) {
	try {
		// Locate the BIT STRING for an uncompressed public key: 03 42 00 04 <32 X> <32 Y>
		var bitStringIdx = der.indexOf(Buffer.from([0x03, 0x42, 0x00]));
		if (bitStringIdx === -1) return false;
		var pubkey = der.slice(bitStringIdx + 3, bitStringIdx + 68); // 65 bytes: 04 + 32 + 32
		if (pubkey.length !== 65 || pubkey[0] !== 0x04) return false;

		var encoding = ValidationUtils.isValidHexadecimal(signature) ? 'hex' : 'base64';
		var sigBytes = Buffer.from(signature, encoding);
		var rawCompact = sigBytes.length === 64 ? sigBytes : Buffer.from(ecdsa.signatureImport(sigBytes));
		var compactSig = Buffer.from(ecdsa.signatureNormalize(rawCompact));

		var msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(message);
		var hash = crypto.createHash('sha256').update(msgBuf).digest();
		return ecdsa.ecdsaVerify(compactSig, hash, pubkey);
	} catch(e) {
		console.log('secp256k1 pem verify exception: ' + e);
		return false;
	}
```

**File:** signature.js (L139-161)
```javascript
//we determine start and length of algo/curve identifiers
	if (contentAloneBuffer[1] <= 0x7F){
		if (contentAloneBuffer[2] != 0x30)
			return handle("pem key doesn't have a second sequence");
		var identifiersStart = 4;
		var identifiersLength = contentAloneBuffer[3];
	} else if (contentAloneBuffer[1] == 0x81){
		if (contentAloneBuffer[3] != 0x30) 
			return handle("pem key doesn't have a second sequence");
		var identifiersStart = 5;
		var identifiersLength = contentAloneBuffer[4];
	} else if (contentAloneBuffer[1] == 0x82){
		if (contentAloneBuffer[4] != 0x30) 
			return handle("pem key doesn't have a second sequence");
		var identifiersStart = 6;
		var identifiersLength = contentAloneBuffer[5];
	} else {
		return handle("wrong length tag");
	}

	//we decode the length of identifiers
	if (identifiersLength != 13 && identifiersLength != 16 && identifiersLength != 19 && identifiersLength != 20)
		return handle("wrong identifiers length" + identifiersLength);
```

**File:** test/pem_sig.test.js (L568-585)
```javascript
test.cb('is_valid_sig  secp256k1 base64', t => {
	var trigger = { data: 
		{
			pem_key: "-----BEGIN PUBLIC KEY-----\n\
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEG7dvwfTNoLaqlZPiXoatOr7ru0qW3OE6\n\
wtxsPV3F3i6MFRJgSRCbUChJkG9dqyGh7DqM7xwHn5YdqQ+HwfE4bw==\n\
-----END PUBLIC KEY-----",
			message: "4111c0dfc41d47f56248ccdc9009b98e7516d6f3db806e999ee5f27b574a48d6",
			signature: "MEUCIDbAjd+mtf4gim/5VkZdPnnexnS8hOCrGXMVFTOnO2MsAiEA7VtOW1aGhRaX5fbRCtNTosHCCmMQ7Z+kc76wUuPMMgU="
		}
	};
	
	evalFormulaWithVars({ conn: null, formula:  "is_valid_sig(trigger.data.message, trigger.data.pem_key, trigger.data.signature)", trigger: trigger, objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU' }, (res, complexity) => {
		t.deepEqual(res, true);
		t.deepEqual(complexity, 2);
		t.end();
	})
});
```
