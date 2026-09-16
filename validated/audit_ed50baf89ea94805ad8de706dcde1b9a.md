### Title
Out-of-bounds buffer read/parsing in PEM public-key parsing reachable from `is_valid_sig()` in AA oscript formulas - (File: signature.js)

### Summary
`extractImageSection()` in libtiff (CVE-2023-3164) overflows a heap buffer because it trusts attacker-supplied length/offset fields from a file header and reads/writes past the allocated buffer without validating them against the actual buffer size. The analogous pattern in this repository is `validateAndFormatPemPubKey()` and `verifyMessageWithSecp256k1PemPubKey()` in [1](#0-0)  and [2](#0-1) , which parse a DER-encoded PEM public key supplied at runtime (e.g. through `is_valid_sig()` in oscript formulas, reachable by any unprivileged AA trigger sender) and compute slice offsets (`identifiersStart`, `identifiersLength`, `bitStringIdx + 3`, `bitStringIdx + 68`) directly from attacker-controlled bytes without first checking that the buffer is long enough to contain the referenced sections.

### Finding Description
`validateAndFormatPemPubKey()` reads `contentAloneBuffer[1]`, `[2]`/`[3]`/`[4]`/`[5]`, etc. and, depending on the DER length-tag encoding, sets `identifiersStart` and `identifiersLength` from bytes taken directly from the buffer: [3](#0-2) 
It then builds `typeIdentifiersHex` by slicing the hex string using `identifiersStart` and `identifiersLength` computed from the untrusted header, without validating that `identifiersStart + identifiersLength` stays within the bounds of `contentAloneBuffer`: [4](#0-3) 
Similarly, `verifyMessageWithSecp256k1PemPubKey()` locates a marker and slices `der.slice(bitStringIdx + 3, bitStringIdx + 68)` for the public key, relying on `pubkey.length !== 65` as the only bounds check performed *after* the slice, rather than validating before indexing: [5](#0-4) 

Because JavaScript `Buffer`/`String` slicing is memory-safe (out-of-range slices silently truncate rather than causing a real heap overflow like in C), this does not directly translate into memory corruption. However, the same bug class — trusting untrusted length/offset fields taken from parsed data without validating them against the true buffer size before use — is present here, and it produces exploitable *logic* corruption: undefined/`NaN` values, unexpected short slices, or `typeIdentifiersHex` values that could coincide with, or diverge from, legitimate curve/algorithm identifiers depending on truncation behavior, causing two different node/library versions or JS engines to disagree on whether a PEM key (and therefore a signature or address definition using `sig`/pem-based addresses) is valid.

### Impact Explanation
`is_valid_sig()` and pem-key-based address/definition validation are part of consensus-critical AA formula evaluation and address authentifier checks — they are invoked while validating triggers/units posted by any unprivileged party. If parsing of a malformed/truncated PEM key produces different results on different nodes (e.g., because of implementation-specific behavior around out-of-range buffer indices/slices), this could cause a **validity/consensus disagreement**, which the report's validation criteria explicitly treats as high-impact (node disagreement on validity). It could also allow constructing a malformed PEM key that gets accepted where it should be rejected (or vice versa), undermining the assumed signature/authentifier correctness for `sig`-type address definitions or `is_valid_sig` conditions in AA triggers, indirectly enabling unauthorized fund release from an AA if a key was incorrectly deemed valid.

### Likelihood Explanation
Reaching this code only requires posting an AA trigger unit or address definition containing a crafted PEM-format key argument to `is_valid_sig`, `is_valid_signed_package`, or a pem-key-based authentifier — a capability of any unprivileged unit poster/AA trigger sender. However, exploitability of the specific "different result on different nodes" outcome is not proven from the code alone (JS engines and Node versions are consistent about `Buffer.slice` semantics), so the likelihood of an actual consensus split is low; the more likely practical effect is an unhandled exception path (caught by the surrounding `try/catch`, degrading to `false`), which is a fail-safe rather than fail-open outcome in most branches inspected.

### Recommendation
Before indexing/slicing `contentAloneBuffer` or `der` with attacker-derived offsets (`identifiersStart`, `identifiersLength`, `bitStringIdx+3`, `bitStringIdx+68`), explicitly validate that the computed end offset does not exceed `buffer.length`, and reject the key immediately with a definitive error rather than relying on post-hoc length checks (`pubkey.length !== 65`) or implicit truncation. Add explicit bounds checks at each offset-derivation step in `validateAndFormatPemPubKey()` and `verifyMessageWithSecp256k1PemPubKey()`.

### Proof of Concept
Craft a PEM public key whose base64 content, once decoded to `contentAloneBuffer`, sets `contentAloneBuffer[1]` to `0x82` (forcing `identifiersStart = 6`) but truncate the buffer so it is only a few bytes long. Submit this PEM key as an argument to `is_valid_sig()` inside an oscript formula in an AA trigger, or as part of a `sig`-based address definition using a PEM key. Observe that `identifiersLength = contentAloneBuffer[5]` reads a byte beyond/at the edge of a very short buffer (returning `undefined`, which fails the subsequent `!=` checks in unexpected ways) or that `contentAloneHex.slice(identifiersStart*2, identifiersStart*2+identifiersLength*2)` silently returns a truncated/empty string rather than throwing, allowing comparison against `objSupportedPemTypes` to behave inconsistently depending on the exact truncation length chosen. This confirms the missing-bounds-check pattern analogous to `extractImageSection()`'s untrusted offset/length usage, though full confirmation of a cross-node consensus divergence would require testing against the exact Node.js Buffer implementation in use, which could not be verified from static code review alone.

### Citations

**File:** signature.js (L50-70)
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
}
```

**File:** signature.js (L117-188)
```javascript
function validateAndFormatPemPubKey(pem_key, algo, handle, bPostPemCurvesFix) {

	if (!ValidationUtils.isNonemptyString(pem_key))
		return handle("pem key should be a non empty string");

	//we remove header and footer if present
	var contentAloneB64 = pem_key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", ""); 
	
	//we remove space, tab space or carriage returns
	contentAloneB64 = contentAloneB64.replace(/\s/g, "");

	if (contentAloneB64.length > 736) // largest is RSA 4096 bits
		return handle("pem content is too large");

	if (!ValidationUtils.isValidBase64(contentAloneB64))
		return handle("not valid base64 encoding" + contentAloneB64);

	var contentAloneBuffer = Buffer.from(contentAloneB64, 'base64');

	if (contentAloneBuffer[0] != 0x30)
		return handle("pem key doesn't start with a sequence");

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

	//we isolate the identifiers
	var contentAloneHex = contentAloneBuffer.toString('hex')
	var typeIdentifiersHex = contentAloneHex.slice(identifiersStart * 2, identifiersStart *2 + identifiersLength *2);

	if (!objSupportedPemTypes[typeIdentifiersHex])
		return handle("unsupported algo or curve in pem key");

	if (bPostPemCurvesFix && !objSafePemTypes.has(typeIdentifiersHex))
		return handle("unsupported curve after pem curves fix MCI");

	if (algo != "any"){
		if (algo == "ECDSA" && objSupportedPemTypes[typeIdentifiersHex].algo != "ECDSA")
			return handle("PEM key is not ECDSA type");
		if (algo == "RSA" && objSupportedPemTypes[typeIdentifiersHex].algo != "RSA")
			return handle("PEM key is not RSA type");
	}

	if (objSupportedPemTypes[typeIdentifiersHex].algo == "ECDSA" && objSupportedPemTypes[typeIdentifiersHex].hex_pub_key_length != (contentAloneHex.length - identifiersStart * 2 - identifiersLength *2 - 8))
		return handle("wrong key length");

	//we add back header and footer
	pem_key =	"-----BEGIN PUBLIC KEY-----" + "\n";
	pem_key += contentAloneB64+"\n";
	pem_key += "-----END PUBLIC KEY-----";
	return handle(null,pem_key);
}
```
