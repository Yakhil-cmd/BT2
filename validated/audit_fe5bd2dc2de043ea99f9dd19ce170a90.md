Confirmed: `definition.js` calls `ecdsaSig.verify` (which is `signature.js`'s `verify` function) at the `sig` authentifier evaluation path.

### Title
Unvalidated-length signature buffer passed to native secp256k1 verify may cause authentifier verification bypass or crash - (File: signature.js)

### Summary
`signature.js`'s `verify()` function decodes an attacker-supplied base64 signature string with `Buffer.from(b64_sig, "base64")` and passes it directly into the native `secp256k1` binding's `ecdsaVerify` without first checking that the resulting buffer is exactly 64 bytes, mirroring the CVE-2022-43507 root cause class (a native crypto engine performing signature/buffer operations without adequate length/bounds restriction on attacker-controlled input).

### Finding Description
In `signature.js`: [1](#0-0) 
`verify(hash, b64_sig, b64_pub_key)` converts `b64_sig` straight to a `Buffer` and hands it to `ecdsa.ecdsaVerify` with no explicit length assertion beforehand — the only protection is the surrounding `try/catch`, which assumes the native binding always throws cleanly on malformed input rather than misbehaving.

This function is reached from `definition.js`'s `sig` authentifier evaluation, which is executed for every unit-posting user's signature check: [2](#0-1) 
Here `signature = assocAuthentifiers[path]` is taken directly from the attacker-supplied unit's authentifiers, checked only for truthiness (`if (!signature) return cb2(false);`), and passed to `ecdsaSig.verify` with no length/format validation of the signature string prior to buffer decoding.

While `pubkey` in the `sig` definition is bound-checked (`isStringOfLength(args.pubkey, constants.PUBKEY_LENGTH)` in `definition.js` line 248), the signature value itself has no equivalent length check anywhere on this path before reaching the native cryptographic buffer operation, unlike other call sites (e.g. `formula/evaluation.js`'s `is_valid_sig`) that explicitly cap `evaluated_signature.length > 1024` before calling into `signature.js`.

### Impact Explanation
If the native `secp256k1` binding does not robustly bounds-check the signature buffer length (the exact bug class in CVE-2022-43507 — "improper buffer restrictions... allow escalation of privilege"), an unprivileged unit author could submit a malformed/oversized or undersized base64 "signature" value that triggers undefined behavior in the native addon (out-of-bounds read, crash, or incorrect verification result) instead of a clean `false`. In the worst case this could let attacker-controlled input desynchronize validation outcomes between nodes (nodes crash vs. nodes reject) — a node-disagreement-on-validity condition, or a denial of the node process handling unit validation.

### Likelihood Explanation
Reachable trivially by any unpriviledged party who posts a unit whose author uses a `["sig", {pubkey}]` definition and supplies a crafted `authentifiers.r` value; no special permissions are required. The exploitability, however, hinges entirely on whether the underlying `secp256k1` native binding used by this deployment actually mishandles wrong-length input buffers rather than throwing a JS-catchable error — I could not verify the native binding's internal implementation from this codebase, so this is a plausible but unconfirmed cross-layer analog rather than a proven exploit.

### Recommendation
Add an explicit length check on the decoded signature buffer (`signature.length === 64`) in `signature.js`'s `verify()` (and analogously in `definition.js`'s `sig` case) before calling `ecdsa.ecdsaVerify`, matching the bound-checking pattern already used for `is_valid_sig`/`vrf_verify` in `formula/evaluation.js` (`evaluated_signature.length > 1024` check). This ensures untrusted input never reaches the native crypto call without prior JS-side size validation, regardless of the native binding's own robustness.

### Proof of Concept
```js
// author submits a unit with definition ["sig", {pubkey: <valid 33-byte b64 pubkey>}]
// and authentifiers: { r: "<base64 string decoding to, e.g., 1 byte or 10000 bytes>" }
// definition.js -> validateAuthentifiers -> case 'sig' calls:
ecdsaSig.verify(objValidationState.unit_hash_to_sign, "AA==", pubkey_b64);
// -> Buffer.from("AA==","base64") yields a 1-byte buffer, passed directly into
//    ecdsa.ecdsaVerify(signature, hash, pubkey) with no prior length assertion.
```

**Uncertainty note:** I was not able to inspect the internal C/WASM implementation of the `secp256k1` npm binding used by this project (outside the indexed repo) to confirm whether it actually performs unsafe buffer reads on mis-sized inputs, or whether it always throws a safe JS exception. This finding is submitted as the strongest reachable analog to the CVE's buffer-restriction bug class found in the in-scope validation path, but its concrete memory-safety impact could not be fully proven from the available code alone.

### Citations

**File:** signature.js (L16-25)
```javascript
function verify(hash, b64_sig, b64_pub_key){
	try{
		var signature = Buffer.from(b64_sig, "base64"); // 64 bytes (32+32)
		return ecdsa.ecdsaVerify(signature, hash, Buffer.from(b64_pub_key, "base64"));
	}
	catch(e){
		console.log('signature verification exception: '+e.toString());
		return false;
	}
};
```

**File:** definition.js (L734-754)
```javascript
			case 'sig':
				// ['sig', {algo: 'secp256k1', pubkey: 'base64'}]
				//console.log(op, path);
				var signature = assocAuthentifiers[path];
				if (!signature)
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'secp256k1';
				if (algo === 'secp256k1'){
					if (objValidationState.bUnsigned && signature[0] === "-") // placeholder signature
						return cb2(true);
					var res = ecdsaSig.verify(objValidationState.unit_hash_to_sign, signature, args.pubkey);
					if (!res)
						fatal_error = "bad signature at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported sig algo at path "+path;
					return cb2(false);
				}
				break;
```
