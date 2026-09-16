## Title
Signed-message verification lacks a mandatory network/chain identifier, enabling cross-network replay of `is_valid_signed_package` authorizations - ([File: signed_message.js])

### Summary
Obyte runs several independent networks that share the exact same address-derivation and signature scheme (mainnet, testnet, devnet), distinguished only by the `alt`/`version` constants. `signed_message.validateSignedMessage()`, which is the routine AAs use (via the `is_valid_signed_package` oscript operator) to verify externally-signed data, treats the `version` field as **optional** and never requires or checks any network-identifying field. As a result, a signed package that omits `version` (or uses a value common to multiple deployments) hashes and verifies identically on every network, so it can be captured on one network and replayed on another to satisfy `is_valid_signed_package` in an AA that never intended to trust it there. This is the same root cause as the reported Forwarder bug: a signature-verification routine that never binds the signature to the chain/network it was created for.

### Finding Description
Regular DAG units are protected against cross-network replay because `validation.js` explicitly rejects any unit whose `alt` doesn't match `constants.alt`: [1](#0-0) 

However, `signed_message.js`'s `validateSignedMessage()` — the function used to authenticate off-chain signed messages/packages — allows `["signed_message", "authors", "last_ball_unit", "timestamp", "version"]` and only validates `version` **if it happens to be present**: [2](#0-1) 

There is no `alt` field in the schema at all, and no mandatory network-binding field. The digest that is actually signed and verified is computed by `getSignedPackageHashToSign()`, which simply hashes whatever fields exist in the package (minus `authentifiers`) — it does not inject or require any chain/network identifier: [3](#0-2) 

Consequently, a signed package built without a `version` field (or with a `version` value that happens to be accepted on more than one deployment) is byte-identical and cryptographically valid regardless of which Obyte network (mainnet/testnet/devnet) it is submitted to, because:
- Addresses are derived via `getChash160` from the definition alone, independent of `alt`/`version`, so the same address exists on every network.
- The hash-to-sign and the authentifier check (`ecdsaSig.verify(objValidationState.unit_hash_to_sign, signature, args.pubkey)`) in `definition.js` don't reference network state: [4](#0-3) 

This verification path is reachable by any AA trigger sender through the `is_valid_signed_package` formula operator, which forwards attacker-supplied `trigger.data` fields straight into `validateSignedMessage`: [5](#0-4) 

### Impact Explanation
AA authors use `is_valid_signed_package` as an authentication primitive for off-chain-signed instructions (e.g., signed orders, price attestations, oracle data, or authorization messages) supplied as trigger data. Because verification does not bind the signature to a specific network, a package that was legitimately signed and observed on one Obyte network (including low-value/testnet or devnet where captured signatures are cheap to obtain) can be replayed verbatim as trigger data against an AA on another network (e.g. mainnet) that shares the same signer address/definition, satisfying `is_valid_signed_package` there. Any AA whose logic pays out funds, updates internal accounting, or grants privileges based on this check can be tricked into accepting data/authorization that the signer never intended for that network, resulting in unauthorized AA actions and potential fund loss.

### Likelihood Explanation
Any unprivileged party who can post an AA trigger can attempt this — no special privileges are required. The main precondition is that the intended signer produces (or can be induced to produce) a `signed_message` package without a `version` field, or that they reuse the same signing address/definition across networks, both of which are entirely plausible for oracle-style or cross-deployment use cases. `signMessage()` itself always sets `version: constants.version`, so packages produced by the standard wallet code do carry a network-specific version string; the exposure is greatest for AAs that accept externally/manually constructed `signed_package` objects, or when `version` values collide between deployments (e.g. custom devnets).

### Recommendation
Make the network binding for signed packages explicit and mandatory rather than optional:
- Require a `version`/network field in every signed package accepted by `validateSignedMessage`, rejecting packages that omit it, instead of only validating it "if present" (`signed_message.js`, ~line 136).
- Include `constants.alt` explicitly in the signed-package hash input (`getSignedPackageHashToSign` in `object_hash.js`) so that a package signed on one network can never verify on a network with a different `alt`, mirroring the `objUnit.alt !== constants.alt` check already used for units in `validation.js`.

### Proof of Concept
1. Craft a `signed_package` object containing only `{signed_message, authors}` (no `version`, no `last_ball_unit`), and sign it with a definition/address that exists identically on network A and network B (any `sig` definition, since chash is network-independent).
2. Submit this package on network A as `trigger.data.signed_package` to an AA using `is_valid_signed_package(trigger.data.signed_package, address)` — validation succeeds via `signed_message.validateSignedMessage` / `definition.validateAuthentifiers`.
3. Replay the identical `signed_package` bytes as trigger data to the same (or a compatible) AA deployed on network B. Because `validateSignedMessage` never checks `alt`/network and `version` was never required, the same signature passes verification again on network B, letting the attacker trigger the AA logic that was meant to be authorized only in the context of network A.

### Citations

**File:** validation.js (L275-278)
```javascript
	if (constants.supported_versions.indexOf(objUnit.version) === -1)
		return callbacks.ifUnitError("wrong version");
	if (objUnit.alt !== constants.alt)
		return callbacks.ifUnitError("wrong alt");
```

**File:** signed_message.js (L132-137)
```javascript
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
	if (!('signed_message' in objSignedMessage))
		return handleResult("no signed message");
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
```

**File:** object_hash.js (L97-103)
```javascript
function getSignedPackageHashToSign(signedPackage) {
	var unsignedPackage = _.cloneDeep(signedPackage);
	for (var i=0; i<unsignedPackage.authors.length; i++)
		delete unsignedPackage.authors[i].authentifiers;
	var sourceString = (typeof signedPackage.version === 'undefined' || signedPackage.version === constants.versionWithoutTimestamp) ? getSourceString(unsignedPackage) : getJsonSourceString(unsignedPackage);
	return crypto.createHash("sha256").update(sourceString, "utf8").digest();
}
```

**File:** definition.js (L734-748)
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
```

**File:** formula/evaluation.js (L1659-1701)
```javascript
				var signed_package_expr = arr[1];
				var address_expr = arr[2];
				evaluate(address_expr, function (evaluated_address) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isValidAddress(evaluated_address))
						return setFatalError("bad address in is_valid_signed_package: " + evaluated_address, { arr }, false, cb);
					evaluate(signed_package_expr, async function (signedPackage) {
						if (fatal_error)
							return cb(false);
						if (!(signedPackage instanceof wrappedObject))
							return cb(false);
						signedPackage = signedPackage.obj;
						if (ValidationUtils.hasFieldsExcept(signedPackage, ['signed_message', 'last_ball_unit', 'authors', 'version']))
							return cb(false);
						if (signedPackage.version) {
							if (typeof signedPackage.version !== 'string')
								return cb(false);
							if (signedPackage.version === constants.versionWithoutTimestamp)
								return cb(false);
							const fVersion = parseFloat(signedPackage.version);
							const maxVersion = 4; // depends on mci in the future updates
							if (fVersion > maxVersion)
								return cb(false);
						}
						if (typeof signedPackage.last_ball_unit === 'string') {
							const [row] = await conn.query("SELECT main_chain_index, is_on_main_chain FROM units WHERE unit=?", [signedPackage.last_ball_unit]);
							if (!row || row.main_chain_index > mci || row.main_chain_index === null) // not existing or not stable last ball unit
								return cb(false);
							if (!row.is_on_main_chain && mci >= constants.pemCurvesFixMci) // last ball must be on the MC
								return cb(false);
							if (mci >= constants.pemCurvesFixMci && row.main_chain_index < constants.pemCurvesFixMci) // last ball unit is before the fix
								return setFatalError("last ball unit is before the PEM curves fix", { arr }, false, cb);
						}
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
					});
				});
```
