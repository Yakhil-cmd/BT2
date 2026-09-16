This is the key finding: the `is_valid_signed_package()` off-chain signature scheme used by AAs to validate order-book style signed messages does not bind the signature to any specific verifying AA (no domain separator), which is the direct analog of the Mech Marketplace `domainSeparator` bug.

### Title
Off-chain `signed_message`/`is_valid_signed_package` signatures lack a domain separator binding them to a specific AA, enabling cross-AA signature replay - (File: `signed_message.js`, `object_hash.js`, `formula/evaluation.js`)

### Summary
`object_hash.getSignedPackageHashToSign()` hashes only the `signed_message`, `authors` (minus authentifiers), `last_ball_unit`, `timestamp` and `version` fields of a signed package. Nothing in this hash ties the signature to the particular Autonomous Agent (AA) that is meant to consume/verify it via the `is_valid_signed_package()` oscript function. Any number of different AAs can implement the same order-book/off-chain-signing pattern (as in `test/samples/order_book_exchange.oscript`), and because the hash-to-sign is identical regardless of which AA will process the package, a signed order/message valid for one AA instance is equally valid for any other AA instance that runs the same verification logic — exactly analogous to multiple `MechMarketplace` proxies sharing one immutable `domainSeparator`.

### Finding Description
`getSignedPackageHashToSign()` computes: [1](#0-0) 

It only strips `authentifiers` from the cloned package and hashes the rest (`signed_message`, `authors[].address`/`definition`, `last_ball_unit`, `timestamp`, `version`). There is no field representing "the AA address this signature is intended for" or any other application-specific domain tag.

`validateSignedMessage()` in `signed_message.js` reconstructs the exact same hash and checks the signature against it: [2](#0-1) 

The oscript-exposed wrapper is `is_valid_signed_package(package, address)`, used in `test/samples/order_book_exchange.oscript` to accept off-chain signed orders as AA trigger data: [3](#0-2) 

Because the signed hash contains no AA address / app identifier, a user who signs an order intended for AA₁ (a deployed order-book AA) produces a signature that is byte-for-byte reusable as valid input to AA₂ if AA₂ is another deployment of the same (or structurally identical) order-book AA code — the same class of bug as sharing one `domainSeparator` across multiple `MechMarketplace` proxies of the same implementation. Note this is different from ordinary unit-signing (`getUnitHashToSign`), which is bound to a specific unit's parents/messages/DAG position and therefore isn't directly replayable across contexts; `signed_message`/`is_valid_signed_package` is explicitly designed as an off-chain, reusable, AA-agnostic signature format, so it inherits the missing-domain-separator problem by construction.

### Impact Explanation
Any AA author who builds an off-chain signing scheme on top of `signed_message`/`is_valid_signed_package` (the pattern explicitly supported and demoed by ocore itself, e.g. the order-book exchange sample) is exposed to cross-AA replay of user-signed intents. If two AAs (e.g., two independently deployed order-book/exchange AAs, or a v1/v2 pair sharing base code) both validate signed orders the same way and a user reuses the same address across both, an order signed for AA₁ can be submitted to AA₂ and accepted, causing unintended fund movement, order execution against the wrong balance/asset pool, or double-spend of the "intent" (e.g., filling the same signed order in two different marketplaces simultaneously, draining a user's balance twice). This is a fund-loss/double-spend class issue reachable purely by an unprivileged AA trigger sender relaying a previously-seen signed package to a different AA instance.

### Likelihood Explanation
Likelihood is Medium: it requires (a) an AA developer to adopt the `signed_message`/`is_valid_signed_package` pattern (which ocore itself ships as a reference sample), and (b) more than one such AA instance (or a legitimate AA plus an attacker-deployed clone with identical verification logic) to exist and share signer addresses. Given that AA definitions are frequently parameterized/duplicated (`base_aa`/`params` templates, as seen in `aa_addresses.js` and `storage.readBaseAADefinitionAndParams`), it is realistic for multiple structurally identical AAs to coexist on the same network, making this a practically reachable scenario for any dApp using off-chain order signing.

### Recommendation
Include an application-specific domain separator in the hash computed by `getSignedPackageHashToSign()` — e.g., require/allow the signer to bind the package to a specific `app`/`aa_address`/`asset` field that is mandatory content of `signed_message`, and have `is_valid_signed_package()` (or the AA calling it) verify that this bound value equals `this_address` (the verifying AA's own address) before accepting the package. This mirrors moving `domainSeparator` out of a shared constant into per-instance initialization: each AA (instance) must effectively contribute a instance-unique value into what is signed, so a signature valid for one AA cannot be replayed against another.

### Proof of Concept
1. Deploy two AAs, `AA1` and `AA2`, from the same order-book template (identical logic to `test/samples/order_book_exchange.oscript`), differing only in address.
2. User signs an order (`signed_message`) intended for `AA1` using `signMessage()` in `signed_message.js`, producing `objUnit` whose hash-to-sign is `objectHash.getSignedPackageHashToSign(objUnit)`.
3. Submit the identical `objUnit` as `trigger.data.order1` to `AA2`.
4. `AA2` calls `is_valid_signed_package(trigger.data.order1, order1.address)`, which calls `validateSignedMessage`, recomputing the same `getSignedPackageHashToSign` hash and validating the same signature successfully — despite the order never having been intended for `AA2`. `AA2` then executes/fills the order against its own state (balances, `var['executed_'||id]`), demonstrating replay across a different AA instance without the user ever authorizing interaction with `AA2`. [4](#0-3)

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

**File:** signed_message.js (L117-137)
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

**File:** test/samples/order_book_exchange.oscript (L41-49)
```text
					$id1 = sha256($order1.address || $order1.sell_asset || $order1.buy_asset || $order1.sell_amount || $order1.price || trigger.data.order1.last_ball_unit);
					$id2 = sha256($order2.address || $order2.sell_asset || $order2.buy_asset || $order2.sell_amount || $order2.price || trigger.data.order2.last_ball_unit);

					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;

					if (!is_valid_signed_package(trigger.data.order1, $order1.address)
						OR !is_valid_signed_package(trigger.data.order2, $order2.address))
						return false;
```
