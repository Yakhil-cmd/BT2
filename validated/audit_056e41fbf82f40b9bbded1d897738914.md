### Title
Signed packages (`is_valid_signed_package`/`signed_message.js`) lack a mandatory network/chain-fork binding, enabling cross-fork replay of off-chain authorizations - ([File: object_hash.js, signed_message.js])

### Summary
Off-chain "signed packages" produced by `signMessage()` and verified by `validateSignedMessage()` / the oscript function `is_valid_signed_package()` are the ocore analog of the reported ERC20Permit issue: a user signs a structured message (e.g., a payment-channel state update or an order-book order) that an Autonomous Agent (AA) later accepts as authorization to move funds, without the signature binding to a fork/network-specific identifier. This is directly analogous to `ERC20Permit`'s `hashStruct` omitting `chainID`.

### Finding Description
The hash that is actually signed for these packages is computed by `getSignedPackageHashToSign()`: [1](#0-0) 

and the fields that are allowed/required in a signed package are enumerated in `validateSignedMessage()`: [2](#0-1) 

Note that:
- `version` is **optional** (`"version" in objSignedMessage`), and it is only checked against the *verifying node's own* `constants.supported_versions`/`constants.bTestnet` config, i.e. an attacker can simply omit it.
- There is no `alt` field (the field ocore units use elsewhere to distinguish mainnet/testnet/devnet, see `constants.alt` and its enforcement in unit validation at [3](#0-2) ) included anywhere in the signed-package schema or in `getSignedPackageHashToSign()`.
- Address derivation itself (`getChash160`) is network-agnostic — it does not fold in `alt`/`GENESIS_UNIT`, so the same address/definition and the same private key are valid identities on any fork/network sharing the same code (mainnet, testnet, devnet, or a post-deployment hard fork), exactly the scenario described in the external report ("Bob... on the new chain... Alice replays the... call on the old chain").

AA authors are expected to manually add fork/context binding fields into their own `signed_message` payload (e.g., the sample AA in `test/samples/payment_channels.oscript` manually checks `signed_message.channel != this_address` and `signed_message.period`): [4](#0-3) 

But the protocol itself provides **no** enforced, non-optional chain/network-fork discriminator in the signed-package schema or hash, so any AA/oscript author who does not manually add such a binding (or who binds only to `this_address`/asset, which are identical across a hard fork) produces signatures that remain valid identically on both sides of a post-deployment fork.

### Impact Explanation
If Obyte ever undergoes a post-deployment chain split (hard fork with a lasting minority chain, analogous to the report's exploit scenario), any AA that relies on `is_valid_signed_package`/`is_valid_sig` for authorizing value transfers (payment channels, off-chain order books, etc.) can have a signed authorization from one side of the fork replayed by any third party on the other side, since the signature carries no fork-specific commitment. This can result in unauthorized draining of AA-held funds (e.g., in a payment channel, the closing/fraud-proof messages could be replayed cross-fork to force an incorrect settlement), i.e. AA fund loss — matching the "concrete unauthorized spending / AA fund loss" impact bar.

### Likelihood Explanation
Exploitation requires a genuine, lasting chain split after deployment (the same precondition as the original report). Given Obyte's history of protocol upgrades gated by MCI thresholds rather than contentious forks, a real chain split is a low-probability but not impossible event; however, once it occurs, exploitation of any deployed AA using signed packages (payment channels, order books, or any third-party AA that verifies `is_valid_signed_package`) is straightforward and requires no privileged access — any holder of a previously-signed package can replay it, matching the "unprivileged... AA trigger sender... private-payment counterparty" reachable actor class.

### Recommendation
Short term: make `getSignedPackageHashToSign()` (and the equivalent `getUnitHashToSign()`/`getDeviceMessageHashToSign()` paths used for off-chain signatures) mandatorily include a fork/network-binding value such as `constants.alt` and/or `constants.GENESIS_UNIT`, and reject signed packages that omit it, rather than treating `version`/network-binding as optional fields in `validateSignedMessage()`.

Long term: document that any oscript/AA relying on `is_valid_signed_package`/`is_valid_sig` for authorization MUST explicitly bind the signed content to the target address, asset, and a fork-specific identifier, and provide a built-in helper/field (e.g., a required `network` or `genesis` field validated by `signed_message.js`) so AA authors are not solely responsible for replay protection across chain splits.

### Proof of Concept
1. Address `A` (same definition, hence same chash160) exists identically on mainnet and on a resulting fork chain `F` after a hard fork.
2. On mainnet, the owner of `A` signs a payment-channel closing package via `signMessage()`, producing `objSignedMessage` with `signed_message = {channel: AA_address, period: N, amount_spent: X}` and no `version`/fork-binding field, hashed via `getSignedPackageHashToSign()` ( [1](#0-0) ).
3. On chain `F`, the identical AA definition and address `A` still exist. A counterparty possessing the mainnet-signed package submits it as `trigger.data.sentByPeer` to the AA replica on `F`.
4. The AA's `is_valid_signed_package(trigger.data.sentByPeer, address)` call ( [5](#0-4) ) invokes `signed_message.validateSignedMessage()` ( [6](#0-5) ), which performs no check binding the package to chain `F` specifically, and the signature verifies successfully, letting the attacker force the same settlement/spend on chain `F` that was authorized only for mainnet.

### Citations

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

**File:** signed_message.js (L130-196)
```javascript
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

**File:** validation.js (L277-278)
```javascript
	if (objUnit.alt !== constants.alt)
		return callbacks.ifUnitError("wrong alt");
```

**File:** test/samples/payment_channels.oscript (L107-112)
```text
					if (trigger.data.sentByPeer.signed_message.channel != this_address)
						bounce('signed for another channel');
					if (trigger.data.sentByPeer.signed_message.period != var['period'])
						bounce('signed for a different period of this channel');
					if (!is_valid_signed_package(trigger.data.sentByPeer, $bInitiatedByA ? $addressA : $addressB))
						bounce('invalid signature by peer');
```

**File:** formula/evaluation.js (L1653-1699)
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
```
