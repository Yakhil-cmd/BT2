### Title
Missing built-in replay protection for `is_valid_signed_package` off-chain signed messages used by AAs - (File: `signed_message.js`)

### Summary
`is_valid_signed_package()`/`signed_message.validateSignedMessage()` verify only that a `signed_message` payload was authentically signed by the claimed address and (optionally) references a valid `last_ball_unit`. Nothing in the schema or in the core validation logic ties the signature to a single use: there is no nonce, sequence counter, or "already consumed" marker. Exactly like the `ECDSAPPSOracle` bug, where a validator-quorum-signed price update could be re-submitted verbatim to corrupt `SuperVault`/`SuperVaultStrategy` accounting, a signed off-chain package (order, payment-channel state update, etc.) accepted by this primitive can be resubmitted as AA trigger data an unlimited number of times unless the *AA author* manually implements deduplication.

### Finding Description
`signed_message.validateSignedMessage()` [1](#0-0)  only checks:
- the object has allowed fields (`signed_message`, `authors`, `last_ball_unit`, `timestamp`, `version`),
- the author addresses/definitions are correct and sorted,
- the `last_ball_unit` (if present) exists and is stable,
- the authentifiers verify against `getSignedPackageHashToSign()`.

`getSignedPackageHashToSign()` hashes the message content plus `last_ball_unit`/`version`/`authors`, but includes **no unique, single-use nonce** and no binding to "has this exact package already been consumed by this specific AA state" [2](#0-1) .

The formula function `is_valid_signed_package` in `formula/evaluation.js` wraps this validator and is directly reachable from AA trigger data supplied by an ordinary, unprivileged trigger sender: it evaluates the `signedPackage` argument taken straight from `trigger.data`, checks structural/version/`last_ball_unit` constraints, and then calls `signed_message.validateSignedMessage()` [3](#0-2) . Nothing here prevents the same `signedPackage` object from being submitted again in a later trigger — the only thing that changes between calls is the surrounding unit hash, which the validator never checks.

Because there is no automatic anti-replay mechanism, the core is delegating the single-use guarantee entirely to whichever AA author consumes the primitive. This is exactly the same design flaw the external report identifies: a signature scheme without a nonce/domain-binding field is fundamentally replayable, and any consumer that doesn't add its own replay guard is vulnerable. The ocore team's own reference sample AAs make this dependency explicit — `order_book_exchange.oscript` manually derives an id (`sha256(... || last_ball_unit)`) and checks/sets `var['executed_' || $id]` before/after honoring a signed order [4](#0-3) [5](#0-4) ; `payment_channels.oscript` relies on a `period` counter embedded in the signed message and manually bumped in AA state, rather than on any protection from `is_valid_signed_package` itself [6](#0-5) [7](#0-6) .

### Impact Explanation
Any AA that uses `is_valid_signed_package` to authorize fund movement (order matching, payment-channel closing/withdrawal, escrow release, oracle-style price attestation, etc.) **without independently implementing an explicit nonce/used-flag check** is vulnerable to signature replay: an unprivileged trigger sender can resend the identical signed package to re-trigger the same state transition (e.g., double-crediting a balance, re-applying a stale channel-closing state, or double-spending a matched order), causing AA fund loss/drain or corrupted share/balance accounting — the same class of impact described in the report for `SuperVault`/`SuperVaultStrategy`. Because the core primitive itself provides zero replay protection, the security of every AA that uses it hinges entirely on correct, non-obvious boilerplate that the AA author must remember to add.

### Likelihood Explanation
High for any AA author who doesn't explicitly replicate the sample's dedup pattern (`sha256(...) -> var['executed_...']`, or a period/nonce field checked and only-once incremented in state). Since `is_valid_signed_package` is a documented, publicly available oscript primitive intended precisely for constructs like order books and payment channels, and the "safe" way to use it is not enforced by the interpreter, this is a footgun that a malicious trigger sender can trivially exploit against any AA that omits the guard — no privileged access, hub/node compromise, or key leak required, only normal unit posting.

### Recommendation
Harden the primitive at the core level rather than relying solely on documentation/sample code:
- Add first-class replay protection to `signed_message`/`is_valid_signed_package`, e.g. require and validate a caller-supplied unique identifier (nonce) that is automatically recorded/checked per-AA (similar to how `last_ball_unit` is already checked), so a given `(address, signed_message)` combination cannot satisfy `is_valid_signed_package` twice for the same consuming AA state root.
- At minimum, extend `getSignedPackageHashToSign()`/`validateSignedMessage()` documentation and interpreter-level warnings to make the single-use responsibility explicit, and consider exposing a built-in helper (e.g. `consume_signed_package`) that atomically checks-and-marks usage in AA state, so AA authors are not required to hand-roll the `sha256(...) -> var['executed_...']` pattern correctly themselves.
- Audit all bundled sample/reference AAs (`order_book_exchange.oscript`, `payment_channels.oscript`, etc.) to ensure the anti-replay pattern is airtight, since these samples are widely copied as templates.

### Proof of Concept
1. Deploy (or imagine) an AA that authorizes a payment based solely on `is_valid_signed_package(trigger.data.package, signer_address)` being true, without deriving and checking a `var['executed_' || hash(...)]` flag (i.e., omitting the pattern shown in `order_book_exchange.oscript`).
2. Off-chain, the signer produces one signed package (e.g., "pay 100 to X") per `signMessage()` [8](#0-7) .
3. A user submits a trigger unit containing this package as `trigger.data.package`; the AA calls `is_valid_signed_package`, which passes through `validateSignedMessage()` [9](#0-8)  and the AA pays out.
4. The same user submits a second, independent trigger unit (different unit hash, same embedded `signedPackage` bytes) to the same AA. `validateSignedMessage()` performs the identical checks and succeeds again, because nothing in the hash-to-sign or in `validateSignedMessage` binds the package to a single consumption — the AA pays out a second time from the same authorization, unless the AA author independently added an explicit dedup guard.

### Citations

**File:** signed_message.js (L28-112)
```javascript
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
	
	function setDefinitionAndLastBallUnit(cb) {
		if (bNetworkAware) {
			composer.composeAuthorsAndMciForAddresses(db, [from_address], signer, function (err, authors, last_ball_unit) {
				if (err)
					return handleResult(err);
				objUnit.authors = authors;
				objUnit.last_ball_unit = last_ball_unit;
				cb();
			});
		}
		else {
			signer.readDefinition(db, from_address, function (err, arrDefinition) {
				if (err)
					throw Error("signMessage: can't read definition: " + err);
				objAuthor.definition = arrDefinition;
				cb();
			});
		}
	}

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
									cb3();
								});
							}
						},
						function(err){
							cb2(err);
						}
					);
				},
				function(err){
					if (err)
						return handleResult(err);
					console.log(require('util').inspect(objUnit, {depth:null}));
					handleResult(null, objUnit);
				}
			);
		});
	});
}
```

**File:** signed_message.js (L117-196)
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
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
	var authors = objSignedMessage.authors;
	if (!ValidationUtils.isNonemptyArray(authors))
		return handleResult("no authors");
	if (!address && !ValidationUtils.isArrayOfLength(authors, 1))
		return handleResult("authors not an array of len 1");
	if (authors.length > constants.MAX_AUTHORS_PER_UNIT)
		return handleResult("too many authors");
	var prev_address = "";
	var the_author;
	for (var i = 0; i < authors.length; i++){
		var author = authors[i];
		if (!ValidationUtils.isNonemptyObject(author))
			return handleResult("author must be a non-empty object");
		if (!ValidationUtils.isValidAddress(author.address))
			return handleResult("not valid address");
		if (author.address <= prev_address)
			return handleResult("author addresses not sorted");
		prev_address = author.address;
		if (ValidationUtils.hasFieldsExcept(author, ['address', 'definition', 'authentifiers']))
			return handleResult("foreign fields in author");
		if ("definition" in author) {
			if (!ValidationUtils.isArrayOfLength(author.definition, 2))
				return handleResult("definition must be an array of length 2");
			if (author.definition[0] === 'autonomous agent')
				return handleResult('AA cannot be defined in authors');
			try {
				if (objectHash.getChash160(author.definition) !== author.address)
					return handleResult("wrong definition: " + objectHash.getChash160(author.definition) + "!==" + author.address);
			}
			catch (e) {
				return handleResult("failed to calc address definition hash: " + e);
			}
		}
		if (author.address === address)
			the_author = author;
		if (!ValidationUtils.isNonemptyObject(author.authentifiers))
			return handleResult("no authentifiers");
		for (let path in author.authentifiers) {
			if (!ValidationUtils.isNonemptyString(author.authentifiers[path]))
				return handleResult("authentifiers must be nonempty strings");
			if (author.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return handleResult("authentifier too long");
		}
	}
	if (!the_author) {
		if (address)
			return handleResult("not signed by the expected address");
		the_author = authors[0];
	}
	try { // check for nulls and empty objects, this makes getChash160 safe on all authors, not just the signer
		string_utils.getJsonSourceString(objSignedMessage);
	}
	catch (e) {
		return handleResult("invalid signed message: " + e);
	}
	var bNetworkAware = ("last_ball_unit" in objSignedMessage);
	if (bNetworkAware && !ValidationUtils.isValidBase64(objSignedMessage.last_ball_unit, constants.HASH_LENGTH))
		return handleResult("invalid last_ball_unit");
	
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

**File:** formula/evaluation.js (L1653-1701)
```javascript
			case 'is_valid_signed_package':
				if (!objValidationState.count_signed_packages)
					objValidationState.count_signed_packages = 0;
				if (objValidationState.count_signed_packages >= constants.MAX_SIGNED_PACKAGES_PER_AA_EVAL && bPostPemCurvesFix)
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
					});
				});
```

**File:** test/samples/order_book_exchange.oscript (L41-45)
```text
					$id1 = sha256($order1.address || $order1.sell_asset || $order1.buy_asset || $order1.sell_amount || $order1.price || trigger.data.order1.last_ball_unit);
					$id2 = sha256($order2.address || $order2.sell_asset || $order2.buy_asset || $order2.sell_amount || $order2.price || trigger.data.order2.last_ball_unit);

					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;
```

**File:** test/samples/order_book_exchange.oscript (L85-85)
```text
						var['executed_' || $id1] = 1;
```

**File:** test/samples/payment_channels.oscript (L43-46)
```text
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
```

**File:** test/samples/payment_channels.oscript (L92-92)
```text
							var['period'] += 1;
```
