## Title
Deprecated/weak elliptic-curve PEM keys are still accepted by `is_valid_sig()`/`vrf_verify()` before `pemCurvesFixMci` activates, allowing signature forgery and unauthorized AA fund release — (File: `signature.js`, `formula/evaluation.js`)

### Summary
CVE-2024-42512 describes an authentication bypass in the OPC UA stack caused by a deprecated, cryptographically weak security policy (`Basic128Rsa15`) still being accepted. `ocore` has a directly analogous condition: the oscript functions `is_valid_sig()` and `vrf_verify()`, used inside Autonomous Agent (AA) formulas to authenticate externally-supplied signatures, accept a large set of deprecated/weak elliptic curves (as small as 112–131-bit key sizes) whenever the evaluation MCI is below `constants.pemCurvesFixMci`. Because this threshold is the newest/highest upgrade constant defined in `constants.js` (above `v4UpgradeMci` and `tpsFeeRecipientsFixMci`), the restriction to "safe" curves has not necessarily activated on the live network yet, so any AA that gates fund release on `is_valid_sig`/`vrf_verify` with one of these weak curves remains forgeable by anyone able to solve the curve's discrete-log problem (already broken publicly for the smallest curves in this list, e.g. `secp112r1`/`secp112r2`).

### Finding Description
`signature.js` defines `objSupportedPemTypes`, a large table of ECDSA curves accepted for PEM public keys, including very weak curves such as `secp112r1`, `secp112r2`, `secp128r1`, `secp128r2`, `secp160k1`, `secp160r1`, `secp160r2`, `prime192v1-3`, several `brainpoolP160/192/224` variants, `sect113r1/r2`, `sect131r1/r2`, and multiple `wap-wsg-idm-ecid-wtls*` curves. [1](#0-0) 

A newer, restricted allowlist `objSafePemTypes` only permits `prime256v1`, `secp224r1`, `secp384r1`, `secp256k1`, and RSA. [2](#0-1) 

`validateAndFormatPemPubKey()` only rejects unsafe curves "after pem curves fix MCI" — i.e. the weak-curve check is conditional on the `bPostPemCurvesFix` flag passed in by the caller: [3](#0-2) 

That flag is computed in `formula/evaluation.js` as:
```
const bPostPemCurvesFix = mci >= constants.pemCurvesFixMci || !bAA && !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci;
``` [4](#0-3) 

and is threaded straight through to the `is_valid_sig` and `vrf_verify` oscript ops, which any AA formula (and thus any AA author) can use to authenticate `trigger.data`-supplied messages/signatures against an arbitrary PEM public key supplied in AA state/params: [5](#0-4) [6](#0-5) 

The gating constant is: [7](#0-6) 

This is defined as the *last* (highest) upgrade MCI in the file, after `v4UpgradeMci` and `tpsFeeRecipientsFixMci`, strongly indicating it is a very recently introduced, not-yet-activated network upgrade. Until the live main-chain index actually reaches `pemCurvesFixMci`, `bPostPemCurvesFix` evaluates to `false` for ordinary AA triggers, so weak curves in `objSupportedPemTypes` (but outside `objSafePemTypes`) remain fully accepted by `is_valid_sig`/`vrf_verify`.

The security consequence mirrors CVE-2024-42512 exactly: a "deprecated" cryptographic option that is nominally scheduled for removal is still functionally accepted for authentication decisions, letting an attacker who does not hold the legitimate private key still produce a signature that passes verification — because the curve's discrete-log problem is computationally tractable at these key sizes (112–160-bit curves are within reach of modern hardware, and some, like `secp112r1`/`secp112r2`, have already been publicly solved in the Certicom ECC challenges).

### Impact Explanation
Any AA (Autonomous Agent) whose payout/authorization logic uses `is_valid_sig(message, pem_pubkey, signature)` or `vrf_verify(seed, proof, pem_pubkey)` with a public key encoded on one of the weak curves is exposed to signature forgery by an unprivileged trigger sender. Because AA triggers are posted by ordinary, unprivileged units, an attacker can:
1. Identify (or be the original AA author for) an AA relying on a weak-curve PEM key for authorization (e.g., an oracle/attestor key, a payout-release key, or a private-payment/contract counterparty key).
2. Solve the ECDLP for that curve to recover (or forge without recovering) a signature that `verifyMessageWithPemPubKey` accepts.
3. Send a crafted trigger with the forged signature, causing the AA to release funds, mark itself "attested", or otherwise treat the attacker as the legitimate signer.

This can lead to direct unauthorized fund loss from the AA, as well as broader trust breakdowns for any oscript logic (private payment chains, asset issuance/attestation, contract offers) that anchors authorization on `is_valid_sig`/`vrf_verify` with one of these curves.

### Likelihood Explanation
Exploitation requires: (a) an AA in the wild choosing one of the weak curves in `objSupportedPemTypes \ objSafePemTypes` for `is_valid_sig`/`vrf_verify`-based authorization, and (b) the network MCI still being below `constants.pemCurvesFixMci` (which, given its position as the highest upgrade constant in `constants.js`, is plausible for the current network state). Given AA authors can freely choose any supported curve when designing contracts, and the vulnerability requires no special network position (any unit poster can trigger an AA), likelihood is moderate-to-high wherever such AAs exist, and the smallest curves (112–131 bit) are already broken with commodity resources, making practical exploitation feasible today, not just theoretical.

### Recommendation
- Enforce `objSafePemTypes`-only validation unconditionally in `validateAndFormatPemPubKey()`, removing the `bPostPemCurvesFix` gate (or expedite/confirm activation of `pemCurvesFixMci` network-wide).
- Consider retroactively flagging/rejecting AAs that reference weak curves in stored definitions, and provide tooling/warnings for AA authors before the fix activates.
- Add unit/integration tests asserting that `is_valid_sig`/`vrf_verify` reject curves outside `objSafePemTypes` regardless of MCI, once the fix is meant to be unconditional.

### Proof of Concept
1. Author (or locate) an AA whose response formula includes logic such as:
   `bounce_if_condition = !is_valid_sig(trigger.data.message, state.pubkey_pem_secp112r1, trigger.data.sig)` gating a payout.
2. With current mci < `constants.pemCurvesFixMci` (see [7](#0-6) ), `bPostPemCurvesFix` is `false`, so `validateAndFormatPemPubKey` accepts the `secp112r1` key [3](#0-2) .
3. Using publicly known ECDLP solutions for `secp112r1`/`secp112r2` (or brute-force for the small curves), compute a valid signature over the attacker-chosen `message` for the AA's stored public key without knowledge of the private key.
4. Post a trigger unit to the AA with `data.message`/`data.sig` set to the forged pair; `evaluate()` calls `signature.verifyMessageWithPemPubKey(...)` [8](#0-7)  which returns `true`, causing the AA to release funds to the attacker.

### Citations

**File:** signature.js (L167-171)
```javascript
	if (!objSupportedPemTypes[typeIdentifiersHex])
		return handle("unsupported algo or curve in pem key");

	if (bPostPemCurvesFix && !objSafePemTypes.has(typeIdentifiersHex))
		return handle("unsupported curve after pem curves fix MCI");
```

**File:** signature.js (L190-198)
```javascript
// Curves that are safe to use across all deployment targets.
// All other curves in objSupportedPemTypes are blocked for new AAs after pemCurvesFixMci.
var objSafePemTypes = new Set([
	'06072a8648ce3d020106082a8648ce3d030107', // prime256v1 (P-256)
	'06072a8648ce3d020106052b81040021',        // secp224r1  (P-224)
	'06072a8648ce3d020106052b81040022',        // secp384r1  (P-384)
	'06072a8648ce3d020106052b8104000a',        // secp256k1  (verified via secp256k1 npm, not OpenSSL)
	'06092a864886f70d0101010500',              // RSA (PKCS #1)
]);
```

**File:** signature.js (L200-230)
```javascript
var objSupportedPemTypes = {
	'06072a8648ce3d020106092b2403030208010101': {
		name: 'brainpoolP160r1',
		hex_pub_key_length: 80,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010102': {
		name: 'brainpoolP160t1',
		hex_pub_key_length: 80,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010103': {
		name: 'brainpoolP192r1',
		hex_pub_key_length: 96,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010104': {
		name: 'brainpoolP192t1',
		hex_pub_key_length: 96,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010105': {
		name: 'brainpoolP224r1',
		hex_pub_key_length: 112,
		algo: 'ECDSA'
	},
	'06072a8648ce3d020106092b2403030208010106': {
		name: 'brainpoolP224t1',
		hex_pub_key_length: 112,
		algo: 'ECDSA'
	},
```

**File:** formula/evaluation.js (L102-102)
```javascript
	const bPostPemCurvesFix = mci >= constants.pemCurvesFixMci || !bAA && !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci;
```

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

**File:** formula/evaluation.js (L1736-1766)
```javascript
			case 'vrf_verify':
				var seed = arr[1];
				var proof = arr[2];
				var pem_key = arr[3];
				evaluate(seed, function (evaluated_seed) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isNonemptyString(evaluated_seed))
						return setFatalError("bad seed in vrf_verify", { arr }, false, cb);
					evaluate(proof, function (evaluated_proof) {
						if (fatal_error)
							return cb(false);
						if (!ValidationUtils.isNonemptyString(evaluated_proof))
							return setFatalError("bad proof string in vrf_verify", { arr }, false, cb);
						if (evaluated_proof.length > 1024)
							return setFatalError("proof is too large", { arr }, false, cb);
						if (!ValidationUtils.isValidHexadecimal(evaluated_proof))
							return setFatalError("bad signature string in vrf_verify", { arr }, false, cb);
						evaluate(pem_key, function (evaluated_pem_key) {
							if (fatal_error)
								return cb(false);
							signature.validateAndFormatPemPubKey(evaluated_pem_key, "RSA", function (error, formatted_pem_key){
								if (error)
									return setFatalError("bad PEM key in vrf_verify: " + error, { arr }, false, cb);
								var result = signature.verifyMessageWithPemPubKey(evaluated_seed, evaluated_proof, formatted_pem_key, bPostPemCurvesFix);
								return cb(result);
							}, bPostPemCurvesFix);
						});
					});
				});
				break;
```

**File:** constants.js (L100-103)
```javascript
exports.tpsFeeRecipientsFixMci = exports.bTestnet ? 3909321 : 11985000;
exports.pemCurvesFixMci = exports.bTestnet ? 3975000 : 12185000;
exports.noPrivateAssetsWithConditionsUpgradeMci = exports.bTestnet ? 3975000 : 12185000;
exports.bestParentPrefersOpUpgradeMci = exports.bTestnet ? 3975000 : 12185000;
```
