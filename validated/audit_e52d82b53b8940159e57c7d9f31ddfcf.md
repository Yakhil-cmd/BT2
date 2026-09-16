### Title
`is_valid_signed_package`/`signed_message.js` signatures omit the network identifier (`alt`), enabling cross-network replay of signed packages - (File: signed_message.js, object_hash.js)

### Summary
`signed_message.js` lets any address holder produce a detached signature over an arbitrary `signed_message` object that AAs (via `is_valid_signed_package` in the oscript formula language) and wallet flows (e.g. `prosaic_contract_response`) accept as proof of authorization. The hash that is actually signed, `objectHash.getSignedPackageHashToSign`, is computed only from `{signed_message, authors, last_ball_unit, version}` and contains no network/chain identifier, unlike full DAG units which include `alt` in their signed content.

### Finding Description
Full units are network-scoped: `getUnitHashToSign` hashes `getNakedUnit(objUnit)`, and `getNakedUnit` deliberately strips only volatile fields (`unit`, commissions, `main_chain_index`, etc.) while preserving `alt`. [1](#0-0) [2](#0-1) 

`alt` is Obyte's network/chain discriminator (mainnet vs testnet vs any other alt-network sharing the same codebase), so a signed unit for one network cannot be validly replayed against another network's DAG.

However, the "signed message" mechanism used for off-chain / detached authorizations does not include `alt` (or any chain id) at all. `signMessage` builds `objUnit = {version, signed_message, authors}` (optionally `last_ball_unit`) with no `alt` field, and signs `objectHash.getSignedPackageHashToSign(objUnit)`: [3](#0-2) [4](#0-3) 

`validateSignedMessage`, which is the verification counterpart used both by wallet code and by the oscript engine, only checks `signed_message`, `authors`, `last_ball_unit`, `timestamp`, `version` fields — again nothing that binds the signature to a particular network: [5](#0-4) 

This routine is directly reachable by an unprivileged AA trigger sender through the `is_valid_signed_package(signed_package, address)` oscript operator: the trigger data supplies an arbitrary `signed_package` object, which is passed straight into `signed_message.validateSignedMessage` after only shape/version checks — no network binding is added by the evaluator either: [6](#0-5) 

Because an address is a `chash160` of its definition and is completely network-independent (the same private key/definition produces the same address on mainnet, testnet, or any other alt-network running the same ocore-based protocol), a `signed_package` legitimately produced and consumed on one network (e.g. testnet, or a private/alt deployment) verifies just as well against an AA on a different network, since the verification hash carries no network tag.

### Impact Explanation
Any AA that accepts externally signed data via `is_valid_signed_package` (e.g. oracle price feeds, off-chain order signing for exchanges, payment-channel state updates — patterns explicitly present in the repo's own sample AAs `order_book_exchange.oscript` and `payment_channels.oscript`) can be fed a signed package that was validly produced for a *different* network/chain sharing the same address space. This allows an attacker who intercepts (or who is the counterparty in) a signed package meant for one network context to replay it against an AA on another network, causing the AA to accept stale/foreign authorization data as if freshly signed for its own chain — potentially triggering unintended fund transfers, order fills at reused parameters, or state transitions the actual signer never intended for that chain. The same weakness applies to `prosaic_contract_response` signed-message handling in the wallet. [7](#0-6) 

### Likelihood Explanation
Exploitability depends on an attacker being able to obtain a signed package produced in one network context and having a target AA/contract with a matching address reachable in another network context, which is a realistic scenario for any project running parallel deployments (mainnet/testnet) of the same AA logic/oracle addresses, or third-party alt-networks based on the same ocore codebase. `last_ball_unit`-based freshness checks constrain replay to the extent that the last_ball_unit must resolve to a stable MC unit at or before the current MCI, but this is a network-local database lookup, not a cross-network binding, so it does not prevent replay across chains that independently reach a compatible MCI state.

### Recommendation
Bind signed packages and detached signed messages to the target network the same way full units already are: include `alt` (and ideally a project/version identifier) inside the object hashed by `getSignedPackageHashToSign`, and require callers of `signed_message.signMessage` / `validateSignedMessage` (including the `is_valid_signed_package` formula op) to populate and check this field against the network the validating node/AA is running on.

### Proof of Concept
1. A user signs a `signed_message` (e.g., a price quote or order) intended for use with an AA deployed on testnet, using `signed_message.signMessage`, producing `objUnit.authors[0].authentifiers` over `objectHash.getSignedPackageHashToSign(objUnit)` — a hash with no `alt`/chain field. [8](#0-7) 
2. Because the address is derived solely from the definition (`chash160`), the same address/definition can exist on mainnet (or any other alt-network using the same ocore code).
3. An attacker submits an AA trigger on mainnet containing the same `signed_package` object in `trigger.data`, calling `is_valid_signed_package(trigger.data.signed_package, address)`. [9](#0-8) 
4. `Definition.validateAuthentifiers` verifies the ECDSA signature against `objValidationState.unit_hash_to_sign` computed the same network-agnostic way, so the signature is accepted on mainnet even though it was produced for testnet, causing the mainnet AA to act on foreign/stale authorization data. [10](#0-9)

### Citations

**File:** object_hash.js (L33-54)
```javascript
function getNakedUnit(objUnit){
	var objNakedUnit = _.cloneDeep(objUnit);
	delete objNakedUnit.unit;
	delete objNakedUnit.headers_commission;
	delete objNakedUnit.payload_commission;
	delete objNakedUnit.oversize_fee;
//	delete objNakedUnit.tps_fee; // cannot be calculated from unit's content and environment, users might pay more than required
	delete objNakedUnit.actual_tps_fee;
	delete objNakedUnit.main_chain_index;
	if (objUnit.version === constants.versionWithoutTimestamp)
		delete objNakedUnit.timestamp;
	//delete objNakedUnit.last_ball_unit;
	if (objNakedUnit.messages){
		for (var i=0; i<objNakedUnit.messages.length; i++){
			delete objNakedUnit.messages[i].payload;
			delete objNakedUnit.messages[i].payload_uri;
		}
	}
	//console.log("naked Unit: ", objNakedUnit);
	//console.log("original Unit: ", objUnit);
	return objNakedUnit;
}
```

**File:** object_hash.js (L89-95)
```javascript
function getUnitHashToSign(objUnit) {
	var objNakedUnit = getNakedUnit(objUnit);
	for (var i=0; i<objNakedUnit.authors.length; i++)
		delete objNakedUnit.authors[i].authentifiers;
	var sourceString = (typeof objUnit.version === 'undefined' || objUnit.version === constants.versionWithoutTimestamp) ? getSourceString(objNakedUnit) : getJsonSourceString(objNakedUnit);
	return crypto.createHash("sha256").update(sourceString, "utf8").digest();
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

**File:** signed_message.js (L27-41)
```javascript
// with bNetworkAware=true, last_ball_unit is added, the definition is taken at this point, and the definition is added only if necessary
function signMessage(message, from_address, signer, bNetworkAware, handleResult){
	if (typeof bNetworkAware === 'function') {
		handleResult = bNetworkAware;
		bNetworkAware = false;
	}
	var objAuthor = {
		address: from_address,
		authentifiers: {}
	};
	var objUnit = {
		version: constants.version,
		signed_message: message,
		authors: [objAuthor]
	};
```

**File:** signed_message.js (L63-93)
```javascript
	var assocSigningPaths = {};
	signer.readSigningPaths(db, from_address, function(assocLengthsBySigningPaths){
		var arrSigningPaths = Object.keys(assocLengthsBySigningPaths);
		assocSigningPaths[from_address] = arrSigningPaths;
		for (var j=0; j<arrSigningPaths.length; j++)
			objAuthor.authentifiers[arrSigningPaths[j]] = repeatString("-", assocLengthsBySigningPaths[arrSigningPaths[j]]);
		setDefinitionAndLastBallUnit(function(){
			var text_to_sign = objectHash.getSignedPackageHashToSign(objUnit);
			async.each(
				objUnit.authors,
				function(author, cb2){
					var address = author.address;
					async.each( // different keys sign in parallel (if multisig)
						assocSigningPaths[address],
						function(path, cb3){
							if (signer.sign){
								signer.sign(objUnit, {}, address, path, function(err, signature){
									if (err)
										return cb3(err);
									// it can't be accidentally confused with real signature as there are no [ and ] in base64 alphabet
									if (signature === '[refused]')
										return cb3('one of the cosigners refused to sign');
									author.authentifiers[path] = signature;
									cb3();
								});
							}
							else{
								signer.readPrivateKey(address, path, function(err, privKey){
									if (err)
										return cb3(err);
									author.authentifiers[path] = ecdsaSig.sign(text_to_sign, privKey);
```

**File:** signed_message.js (L117-136)
```javascript
function validateSignedMessage(conn, objSignedMessage, address, mci, handleResult) {
	if (!handleResult) {
		if (mci) { // validateSignedMessage(conn, objSignedMessage, address, handleResult)
			handleResult = mci;
			mci = undefined;
		}
		else { // validateSignedMessage(objSignedMessage, handleResult)
			handleResult = objSignedMessage;
			objSignedMessage = conn;
			conn = db;
		}
	}
	const max_complexity = (mci >= constants.pemCurvesFixMci) ? 10 : 0;
	if (!ValidationUtils.isNonemptyObject(objSignedMessage))
		return handleResult("signed message must be a non-empty object");
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
	if (!('signed_message' in objSignedMessage))
		return handleResult("no signed message");
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
```

**File:** signed_message.js (L260-289)
```javascript
			validateOrReadDefinition(objAuthor, function (arrAddressDefinition, _last_ball_mci, last_ball_timestamp) {
				last_ball_mci = _last_ball_mci;
				var objUnit = _.clone(objSignedMessage);
				objUnit.messages = []; // some ops need it
				try {
					var objValidationState = {
						unit_hash_to_sign: objectHash.getSignedPackageHashToSign(objSignedMessage),
						last_ball_mci: last_ball_mci,
						last_ball_timestamp: last_ball_timestamp,
						bNoReferences: !bNetworkAware,
						complexity,
						max_complexity,
					};
				}
				catch (e) {
					return cb("failed to calc unit_hash_to_sign: " + e);
				}
				try {
					// passing db as null
					Definition.validateAuthentifiers(
						conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers,
						function (err, res) {
							if (err) // error in address definition
								return cb(err);
							if (!res) // wrong signature or the like
								return cb("authentifier verification failed");
							complexity = objValidationState.complexity;
							cb();
						}
					);
```

**File:** formula/evaluation.js (L1657-1699)
```javascript
					return setFatalError("too many signed packages in evaluation", { arr }, false, cb);
				objValidationState.count_signed_packages++;
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
```

**File:** wallet.js (L558-572)
```javascript
					if (body.signed_message) {
						try{
							var signedMessageJson = Buffer.from(body.signed_message, 'base64').toString('utf8');
							var objSignedMessage = JSON.parse(signedMessageJson);
						}
						catch(e){
							return callbacks.ifError("wrong signed message");
						}
					//	if (objSignedMessage.version !== constants.version)
					//		return callbacks.ifError("wrong version in signed message: " + objSignedMessage.version);
						signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
							if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
								return callbacks.ifError("wrong contract signature");
							processResponse(objSignedMessage);
						});
```
