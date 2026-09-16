### Title
Signed messages used in AA payment channels lack any network/chain-binding, enabling cross-network signature replay - (File: `signed_message.js`, `object_hash.js`, `formula/evaluation.js`)

### Summary
The `signed_message` mechanism (`signMessage`/`validateSignedMessage`) and the `is_valid_signed_package()` oscript primitive that consumes it are used by AAs — most notably payment-channel style AAs — to accept off-chain, peer-signed state updates. The hash that gets signed (`getSignedPackageHashToSign`) contains only the message content, the author addresses/definitions, and optionally `last_ball_unit`/`timestamp`/`version`. It never includes any network- or chain-identifying value (no `alt`, no genesis unit, no network name). Because Obyte/ocore addresses are pure hashes of the address definition (`getChash160`) and do not depend on which network the DAG belongs to, the same private key produces the same address, and the same AA definition produces the same AA address, on every ocore-based network (livenet, testnet, or any other DAG instance running this codebase). A signed package created for one instance of a channel AA can therefore be replayed against an identical AA/address pair on a different network.

### Finding Description
`signMessage()` builds `objUnit = {version, signed_message, authors}` and, in "network aware" mode, adds `last_ball_unit`; the signature covers `objectHash.getSignedPackageHashToSign(objUnit)`, computed in `object_hash.js`: [1](#0-0) 

This hashing helper simply removes `authentifiers` and serializes the rest — no field ties the signature to a particular ledger/network. Compare with `getStrippedUnit()`, which *does* include an `alt` field for regular units: [2](#0-1) 

but `getSignedPackageHashToSign` has no equivalent, and `signMessage`/`validateSignedMessage` never look at `alt` either: [3](#0-2) [4](#0-3) 

`validateSignedMessage` only checks the address, the definition-hash match, and (in network-aware mode) that `last_ball_unit` is a stable, known unit on *some* chain — it has no way of confirming that chain is the one the AA/oscript execution is currently running on: [5](#0-4) 

This validation is invoked by the oscript primitive `is_valid_signed_package`, which AAs use to accept off-chain signed data as part of `trigger.data`: [6](#0-5) 

The shipped payment-channel sample AA relies exactly on this pattern: it authenticates peer-signed balance updates using `is_valid_signed_package(trigger.data.sentByPeer, $addressA/$addressB)` and only additionally checks that `signed_message.channel == this_address` and `signed_message.period == var['period']`: [7](#0-6) 

Neither `this_address` nor `period` is unique across networks: if the identical AA definition (and hence identical `this_address`) and identical channel-partner addresses are instantiated on a second ocore-based network (e.g., a testnet, a private/permissioned deployment, or another altcoin fork of ocore), a signed package that was valid for channel state on network A remains a byte-for-byte valid, unexpired signature for the "same" channel on network B.

### Impact Explanation
An attacker (either channel counterparty, or anyone who obtains a previously-exchanged signed package) could replay a peer's off-chain channel-close/spend message on a second network where the same AA/address pair exists, causing the AA to accept stale or unintended balance-transfer instructions and pay out funds accordingly. This is a direct analog of the reported Solidity issue: the signed authorization is portable to a context (chain) the signer did not intend, resulting in AA fund loss/misallocation on the "wrong" ledger — this satisfies the "AA fund loss" impact bar.

### Likelihood Explanation
Exploitation requires that the same AA address and counterparty addresses genuinely be deployed with funds on more than one ocore-based network — a realistic scenario given that ocore is an open-source framework used to spin up alternative networks/testnets with identical code and often mirrored genesis/witness setups, and address derivation is network-independent by design. Any party who already possesses a valid signed package (a normal part of the payment-channel protocol, exchanged directly between the two parties) can attempt the replay without needing any additional secret.

### Recommendation
Include a network-distinguishing value in the data that gets signed and verified — e.g., add the unit `alt`/network identifier (or a fixed per-network constant) into `getSignedPackageHashToSign()`/`signMessage()`/`validateSignedMessage()`, or require AAs that consume `is_valid_signed_package` to embed a network-specific value (such as the genesis unit hash) inside the signed message payload itself and check it in oscript. This ensures a signature produced for one network cannot be validated as authentic on another.

### Proof of Concept
1. Deploy the sample `payment_channels.oscript` AA (or any AA using `is_valid_signed_package`) with identical source/definition on two ocore-based networks N1 and N2, funded by the same two addresses A and B (achievable because address derivation via `getChash160` does not depend on the network).
2. On N1, party A signs a channel-close message via `signMessage()` producing `objSignedMessage` with `signed_message = {channel: this_address, period: p, amount_spent: X}`.
3. Party B submits this exact `objSignedMessage` as `trigger.data.sentByPeer` to the identical AA instance on N2.
4. `is_valid_signed_package` → `signed_message.validateSignedMessage()` succeeds because none of the checks in `signed_message.js` or `object_hash.getSignedPackageHashToSign` reference network identity; the AA on N2 processes the close/spend using state/balance that was never actually agreed for N2, leading to incorrect fund disbursement.

### Citations

**File:** object_hash.js (L67-87)
```javascript
function getStrippedUnit(objUnit) {
	var bVersion2 = (objUnit.version !== constants.versionWithoutTimestamp);
	var objStrippedUnit = {
		content_hash: getUnitContentHash(objUnit),
		version: objUnit.version,
		alt: objUnit.alt,
		authors: objUnit.authors.map(function(author){ return {address: author.address}; }) // already sorted
	};
	if (objUnit.witness_list_unit)
		objStrippedUnit.witness_list_unit = objUnit.witness_list_unit;
	else if (objUnit.witnesses)
		objStrippedUnit.witnesses = objUnit.witnesses;
	if (objUnit.parent_units){
		objStrippedUnit.parent_units = objUnit.parent_units;
		objStrippedUnit.last_ball = objUnit.last_ball;
		objStrippedUnit.last_ball_unit = objUnit.last_ball_unit;
	}
	if (bVersion2)
		objStrippedUnit.timestamp = objUnit.timestamp;
	return objStrippedUnit;
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

**File:** signed_message.js (L28-61)
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
```

**File:** signed_message.js (L117-144)
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
```

**File:** signed_message.js (L193-253)
```javascript
	var bNetworkAware = ("last_ball_unit" in objSignedMessage);
	if (bNetworkAware && !ValidationUtils.isValidBase64(objSignedMessage.last_ball_unit, constants.HASH_LENGTH))
		return handleResult("invalid last_ball_unit");
	
	function validateOrReadDefinition(objAuthor, cb, bRetrying) {
		var bHasDefinition = ("definition" in objAuthor);
		if (bNetworkAware) {
			conn.query("SELECT main_chain_index, timestamp FROM units WHERE unit=?", [objSignedMessage.last_ball_unit], function (rows) {
				if (rows.length === 0) {
					var network = require('./network.js');
					if (!conf.bLight && !network.isCatchingUp() || bRetrying)
						return handleResult("last_ball_unit " + objSignedMessage.last_ball_unit + " not found");
					if (conf.bLight)
						network.requestHistoryFor([objSignedMessage.last_ball_unit], [objAuthor.address], function () {
							validateOrReadDefinition(objAuthor, cb, true);
						});
					else
						eventBus.once('catching_up_done', function () {
							// no retry flag, will retry multiple times until the catchup is over
							validateOrReadDefinition(objAuthor, cb);
						});
					return;
				}
				bRetrying = false;
				var last_ball_mci = rows[0].main_chain_index;
				var last_ball_timestamp = rows[0].timestamp;
				storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, {
					ifDefinitionNotFound: function (definition_chash) { // first use of the definition_chash (in particular, of the address, when definition_chash=address)
						if (!bHasDefinition) {
							if (!conf.bLight || bRetrying)
								return handleResult("definition expected but not provided");
							var network = require('./network.js');
							return network.requestHistoryFor([], [objAuthor.address], function () {
								validateOrReadDefinition(objAuthor, cb, true);
							});
						}
						if (objectHash.getChash160(objAuthor.definition) !== definition_chash)
							return handleResult("wrong definition: "+objectHash.getChash160(objAuthor.definition) +"!=="+ definition_chash);
						cb(objAuthor.definition, last_ball_mci, last_ball_timestamp);
					},
					ifFound: function (arrAddressDefinition) {
						if (bHasDefinition)
							return handleResult("should not include definition");
						cb(arrAddressDefinition, last_ball_mci, last_ball_timestamp);
					}
				});
			});
		}
		else {
			if (!bHasDefinition)
				return handleResult("no definition");
			try {
				if (objectHash.getChash160(objAuthor.definition) !== objAuthor.address)
					return handleResult("wrong definition: " + objectHash.getChash160(objAuthor.definition) + "!==" + objAuthor.address);
			} catch (e) {
				return handleResult("failed to calc address definition hash: " + e);
			}
			// no last_ball_unit of its own; before the fix, always behave as before (-1) to keep old units re-evaluating the same way
			cb(objAuthor.definition, (mci >= constants.pemCurvesFixMci) ? mci : -1, 0);
		}
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

**File:** test/samples/payment_channels.oscript (L40-49)
```text
							if (trigger.data.sentByPeer){
								if (trigger.data.sentByPeer.signed_message.channel != this_address)
									bounce('signed for another channel');
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
								$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
								if ($transferredFromPeer < 0)
									bounce('bad amount spent by peer: ' || $transferredFromPeer);
```
