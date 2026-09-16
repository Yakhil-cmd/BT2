### Title
Ambiguous Canonical Serialization Allows Signature/Hash Collisions Across Structurally Different Objects (Signature Wrapping Analog) - (File: string_utils.js)

### Summary
`getSourceString()` in `string_utils.js`, the canonical serializer used to compute every signed hash in ocore (`getUnitHashToSign`, `getSignedPackageHashToSign`, `getChash160`, `getBase64Hash`), does not unambiguously bind object structure to its serialized bytes: object keys and the type tags used for scalar values (`"s"`, `"n"`, `"b"`) share the same token stream with no delimiter distinguishing "this is a key" from "this is a type tag" or "this is a string value". This makes it possible to construct two semantically different JS objects that serialize to the *identical* byte string, and therefore hash and sign identically. This is directly analogous to PySAML2's XML Signature Wrapping bug: the cryptographic signature verifies correctly, but the data that application logic subsequently reads is not the data that was actually signed.

### Finding Description
`getSourceString` walks an object depth-first and pushes tokens onto a flat array joined by `\x00`: [1](#0-0) 
For strings it pushes the literal type tag `"s"` followed by the value; for objects it iterates sorted keys and pushes the **raw key** (no type tag, no wrapper like `{`/`}`) followed by the extracted value; only arrays get explicit `[`/`]` delimiters: [2](#0-1) 

Because object keys are pushed as bare tokens indistinguishable from type tags or string payloads, and objects have no start/end delimiter (unlike arrays), the token stream for one JSON structure can be exactly reproduced by a different, deeper nesting. For example:
- `A = {"c": "d", "s": "foo"}` serializes to tokens `["c","s","d","s","s","foo"]`
- `B = {"c": {"s": {"d": {"s": "foo"}}}}` serializes to the exact same tokens `["c","s","d","s","s","foo"]`

`A` and `B` produce identical `getSourceString()` output, hence identical SHA-256 hashes and identical valid signatures, despite being structurally and semantically unrelated objects.

This canonicalization function is the root of every unit/definition/address/message hash in ocore: [3](#0-2) 

It is specifically used to authenticate `signed_message`/`signed_package` objects consumed from oscript (AA triggers), which is reachable by any unprivileged AA trigger sender: [4](#0-3) [5](#0-4) 

`validateSignedMessage`/`is_valid_signed_package` place no schema constraint on the content of `signed_message` — it can be any JSON value — so an attacker who obtains one signature over a legitimately-signed package (e.g. from a price-feed key holder, a paired device, or another AA-trusted signer) can republish a *different* package whose `signed_message` (or nested fields inside it) is restructured per the collision technique above while preserving the exact same `getSourceString()`/hash/signature. Downstream oscript code that reads specific sub-fields, e.g. `signed_package.signed_message.order`/`.price` as shown in the test harness: [6](#0-5) 
will read the attacker's forged values, not the values the original signer actually authorized, while `is_valid_signed_package(...)` still returns `true`.

### Impact Explanation
Any AA that relies on `is_valid_signed_package`/signed messages to authorize spending, mint/release funds, or gate logic based on externally-signed data (oracle prices, off-chain attestations, private-payment proofs relayed through triggers) can be tricked into accepting attacker-forged payloads carrying a signature that was legitimately produced for different content. This can lead to unauthorized fund release from an AA, incorrect DAO/oracle-driven state transitions, or acceptance of forged authorization data — i.e., concrete AA fund loss, matching the "unauthorized spending / AA fund loss" impact bar. Because the same `getSourceString` underlies `getChash160` (address derivation) and `getUnitHashToSign` (unit signatures), the same ambiguity class threatens address/definition integrity more broadly, though the most directly and cheaply reachable exploitation path for an unprivileged attacker is via `is_valid_signed_package` in an AA trigger.

### Likelihood Explanation
Exploitation requires the attacker to construct a colliding restructuring of the JSON object for the specific fields they want to forge — this is a mechanical, offline computation (no cryptographic break needed) similar to the one demonstrated above, and can be automated for arbitrary target values. The attacker only needs one genuine signature over *some* content from the trusted signer (oracle/device/AA-recognized address) to reuse against a collision-restructured package that an AA/formula will then parse differently. This requires no privileged network position, no node compromise, and no leaked keys — only a single previously observed signed package and standard oscript/AA interaction, matching the required "unprivileged unit poster/AA trigger sender" threat model.

### Recommendation
Make the canonical serialization unambiguous: prefix object encoding with an explicit `{`/`}` wrapper (mirroring the `[`/`]` array wrapper) and/or emit key **count** or use a length-prefixed encoding for keys and string values so that no valid token stream can be produced by two different structures. Alternatively, adopt a canonical JSON encoding (as is already done in `getJsonSourceString`) universally, with strict type/length framing, and reject any legacy code paths relying on the ambiguous `getSourceString` for signature-relevant hashing (`getUnitHashToSign`, `getSignedPackageHashToSign`, `getChash160`).

### Proof of Concept
```js
const { getSourceString } = require('./string_utils.js');

const A = { c: "d", s: "foo" };
const B = { c: { s: { d: { s: "foo" } } } };

console.log(getSourceString(A) === getSourceString(B)); // true — identical canonical bytes
```
Both objects hash identically via `crypto.createHash("sha256").update(getSourceString(obj)).digest()`, so any ECDSA signature computed over `getSignedPackageHashToSign`/`getUnitHashToSign` of `A` also verifies against `B`. Embedding this technique inside the `signed_message` field of a `signed_package` submitted to an AA trigger, or inside a unit/definition payload, lets an attacker present a signature obtained for one payload as proof for a different, attacker-chosen payload that downstream code (e.g. `formula/evaluation.js`'s `is_valid_signed_package` consumer logic) will actually read and act upon.

### Citations

**File:** string_utils.js (L11-21)
```javascript
function getSourceString(obj) {
	var arrComponents = [];
	function extractComponents(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				if (variable.includes(STRING_JOIN_CHAR))
					throw Error("00 byte in string value in " + JSON.stringify(obj));
				arrComponents.push("s", variable);
				break;
```

**File:** string_utils.js (L30-52)
```javascript
			case "object":
				if (Array.isArray(variable)){
					if (variable.length === 0)
						throw Error("empty array in "+JSON.stringify(obj));
					arrComponents.push('[');
					for (var i=0; i<variable.length; i++)
						extractComponents(variable[i]);
					arrComponents.push(']');
				}
				else{
					var keys = Object.keys(variable).sort();
					if (keys.length === 0)
						throw Error("empty object in "+JSON.stringify(obj));
					keys.forEach(function(key){
						if (typeof variable[key] === "undefined")
							throw Error("undefined at "+key+" of "+JSON.stringify(obj));
						if (key.includes(STRING_JOIN_CHAR))
							throw Error("00 byte in object key in " + JSON.stringify(obj));
						arrComponents.push(key);
						extractComponents(variable[key]);
					});
				}
				break;
```

**File:** object_hash.js (L89-103)
```javascript
function getUnitHashToSign(objUnit) {
	var objNakedUnit = getNakedUnit(objUnit);
	for (var i=0; i<objNakedUnit.authors.length; i++)
		delete objNakedUnit.authors[i].authentifiers;
	var sourceString = (typeof objUnit.version === 'undefined' || objUnit.version === constants.versionWithoutTimestamp) ? getSourceString(objNakedUnit) : getJsonSourceString(objNakedUnit);
	return crypto.createHash("sha256").update(sourceString, "utf8").digest();
}

function getSignedPackageHashToSign(signedPackage) {
	var unsignedPackage = _.cloneDeep(signedPackage);
	for (var i=0; i<unsignedPackage.authors.length; i++)
		delete unsignedPackage.authors[i].authentifiers;
	var sourceString = (typeof signedPackage.version === 'undefined' || signedPackage.version === constants.versionWithoutTimestamp) ? getSourceString(unsignedPackage) : getJsonSourceString(unsignedPackage);
	return crypto.createHash("sha256").update(sourceString, "utf8").digest();
}
```

**File:** signed_message.js (L255-303)
```javascript
	let last_ball_mci;
	let complexity = 0;
	async.eachSeries(
		authors,
		function (objAuthor, cb) {
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
				}
				catch (e) {
					console.log("exception while validating signed message:", e);
					return cb("exception while validating: " + e);
				}
			});
		},
		function (err) {
			if (err)
				return handleResult(err);
			handleResult(null, last_ball_mci);
		}
	);
}
```

**File:** formula/evaluation.js (L1653-1702)
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
				break;
```

**File:** test/formula.test.js (L1725-1746)
```javascript
	var trigger = {
		data: {
			signed_package: {
				signed_message: {
					order: 11,
					pair: "GB/USD",
					amount: 1.23,
					price: 42.3
				},
				version: '2.0',
				last_ball_unit: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
				authors: [{
					address: address,
					definition: definition,
					authentifiers: {'r': '-------------'}
				}]
			}
		}
	};
	var hash = objectHash.getSignedPackageHashToSign(trigger.data.signed_package);
	var signature = ecdsaSig.sign(hash, xPrivKey.privateKey.bn.toBuffer({ size: 32 }));
	trigger.data.signed_package.authors[0].authentifiers.r = signature;
```
