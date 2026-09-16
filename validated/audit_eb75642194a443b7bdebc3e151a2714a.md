### Title
Missing network (`alt`) binding in signed-package validation allows cross-network replay of signed messages used to authorize AA fund transfers - (File: `signed_message.js`, `object_hash.js`)

### Summary
`validateSignedMessage()` in `signed_message.js` and the hash-to-sign routine `getSignedPackageHashToSign()` in `object_hash.js` never check or bind the signed package to the network identifier (`alt`). Regular units are protected against cross-network replay because `validate()` in `validation.js` explicitly rejects a unit whose `alt` field doesn't match `constants.alt`, but the "signed package"/"signed message" object type — which is consumed directly by AA oscript via `is_valid_signed_package` and by wallet flows such as `arbiter_contract_response` — has no such check anywhere in its schema or hash computation. This is the same bug class as the reported `static_validate_system_transaction` issue: a message/transaction is accepted as valid without verifying it was produced for the correct chain/network context.

### Finding Description
For ordinary units, chain/network separation is enforced explicitly: [1](#0-0) 
This mirrors the EIP-155 chain-id check described in the report — units are rejected if their `alt` (network identifier) doesn't match this node's configured network.

However, "signed packages" (the payload structure used by `is_valid_signed_package` in AA oscript and by device-message signature flows like `arbiter_contract_response`) are validated by a completely separate code path, `validateSignedMessage()`: [2](#0-1) 
The allowed field list is `["signed_message", "authors", "last_ball_unit", "timestamp", "version"]` — there is no `alt` field at all, and no check against `constants.alt`.

The hash that is actually signed by the user's private key is computed by `getSignedPackageHashToSign()`: [3](#0-2) 
This hashes only the cloned package object (`signed_message`, `authors`, `last_ball_unit`, `version`, `timestamp`) — again, no network/chain identifier is included anywhere in the signed bytes.

Address derivation itself (`getChash160`) is also independent of `alt`: [4](#0-3) 
so the same address/private key produces identical signatures regardless of which Obyte-protocol network (mainnet, testnet, or any other fork/altcoin sharing this codebase and constants) the signature was intended for.

This signed-package structure is consumed inside AA oscript evaluation to authorize actions based on a user's off-chain signature: [5](#0-4) 
and in wallet flows that gate financial/contractual actions on a peer's signature, e.g. arbiter contract acceptance: [6](#0-5) 

Because neither the schema check, the hash-to-sign computation, nor `Definition.validateAuthentifiers` binds the signature to a specific network, a signed package legitimately produced by a user for one network context can be replayed as a valid signed package on a different network context where the address (and its definition) happen to resolve the same way.

### Impact Explanation
An AA that uses `is_valid_signed_package(...)` to gate a payout, unlock, or state transition on an off-chain user signature can be tricked into accepting a signed package that the user never intended to authorize in that specific network context, because the signature carries no chain/network binding. This is analogous to the reported issue's impact (validator/system state accepting an unintended transaction due to missing chain-id binding) — here the consequence is an AA authorizing fund release or a wallet-layer contract action (e.g., `arbiter_contract_response`) based on a signature that should not be considered valid for this particular network, resulting in unauthorized AA fund loss/release or invalid contract state acceptance.

### Likelihood Explanation
Exploitation requires only a signed package obtained/observed from another network context (achievable by any unprivileged user who can post AA triggers or exchange signed device messages, matching the "unprivileged unit poster/AA trigger sender" reachability requirement) and an AA or wallet flow relying on `is_valid_signed_package`/`validateSignedMessage` for authorization — no special privileges are needed, and the missing check is a straightforward code-review-detectable omission (mirroring how the original report's issue was found).

### Recommendation
Add `alt` (or an equivalent network/chain identifier) as a required, fixed field of the signed-package schema in `signed_message.js`'s `hasFieldsExcept` allow-list, validate it against `constants.alt`, and include it in the bytes hashed by `getSignedPackageHashToSign()` in `object_hash.js`, so signatures produced for one network cannot be replayed as valid on another.

### Proof of Concept
1. On Network A (e.g., a testnet deployment sharing the ocore codebase/constants but with different `constants.alt`), a user signs a package `{signed_message, authors, last_ball_unit, version}` via `signMessage()` in `signed_message.js`.
2. The resulting signed package (and its signature) is captured/observed by an attacker.
3. The attacker submits the same signed package to an AA trigger on Network B (mainnet) whose oscript uses `is_valid_signed_package(signedPackage, address)` to authorize a payout to `address`.
4. `validateSignedMessage()` (`signed_message.js:117-303`) and `Definition.validateAuthentifiers` accept the package as valid because no field or hash component ties the signature to Network A specifically — the AA on Network B incorrectly treats the replayed signature as proof of the user's intent on Network B, releasing funds it should not have released.

### Citations

**File:** validation.js (L275-278)
```javascript
	if (constants.supported_versions.indexOf(objUnit.version) === -1)
		return callbacks.ifUnitError("wrong version");
	if (objUnit.alt !== constants.alt)
		return callbacks.ifUnitError("wrong alt");
```

**File:** signed_message.js (L130-137)
```javascript
	if (!ValidationUtils.isNonemptyObject(objSignedMessage))
		return handleResult("signed message must be a non-empty object");
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
	if (!('signed_message' in objSignedMessage))
		return handleResult("no signed message");
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
```

**File:** object_hash.js (L10-13)
```javascript
function getChash160(obj) {
	var sourceString = (Array.isArray(obj) && obj.length === 2 && obj[0] === 'autonomous agent') ? getJsonSourceString(obj) : getSourceString(obj);
	return chash.getChash160(sourceString);
}
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

**File:** formula/evaluation.js (L1666-1699)
```javascript
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
```

**File:** wallet.js (L924-936)
```javascript
					if (body.signed_message) {
						try{
							var signedMessageJson = Buffer.from(body.signed_message, 'base64').toString('utf8');
							var objSignedMessage = JSON.parse(signedMessageJson);
						}
						catch(e){
							return callbacks.ifError("wrong signed message");
						}
						signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
							if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
								return callbacks.ifError("wrong contract signature");
							processResponse(objSignedMessage);
						});
```
