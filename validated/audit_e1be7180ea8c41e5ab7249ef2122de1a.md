Based on my investigation, the strongest analog to the LGO `DOMAIN_SEPARATOR` replay-attack bug class is in `is_valid_signed_package()` / `signed_message.validateSignedMessage()`, which — like the unpatched LGO contract — computes a signature-verification hash purely from message content plus signer address, with no built-in binding to the specific AA (contract instance) that is meant to consume it.

### Title
Missing Domain Separation in `is_valid_signed_package`/`validateSignedMessage` Enables Cross-AA Signature Replay - (File: signed_message.js, object_hash.js)

### Summary
The oscript primitive `is_valid_signed_package(signed_package, address)` verifies off-chain signed packages via `signed_message.validateSignedMessage()`, which hashes the package with `objectHash.getSignedPackageHashToSign()`. This hash-to-sign includes only `signed_message`, `authors`, `last_ball_unit`, and `version` — nothing that ties the signature to the specific AA (`this_address`), asset, or application context that is meant to consume it. This mirrors the LGO `DOMAIN_SEPARATOR` bug: a signature valid for one “application” (one AA instance/purpose) can be replayed verbatim against a different AA (or a different code path of the same AA template deployed at another address) as long as the `signed_message` JSON body happens to satisfy that other AA's own field checks.

### Finding Description
`object_hash.js` defines:
```
function getSignedPackageHashToSign(signedPackage) {
    var unsignedPackage = _.cloneDeep(signedPackage);
    for (var i=0; i<unsignedPackage.authors.length; i++)
        delete unsignedPackage.authors[i].authentifiers;
    var sourceString = ... 
    return crypto.createHash("sha256").update(sourceString, "utf8").digest();
}
``` [1](#0-0) 

This is the exact analogue of the missing `DOMAIN_SEPARATOR`: it never includes any identifier of *which* consuming contract/AA the signature is intended for. `signed_message.validateSignedMessage()` only checks that the `authors[].address` matches the `address` parameter passed by the calling AA, and that the definition hashes to that address — it performs no validation of what application/context the message is meant for: [2](#0-1) 

The oscript evaluator's `is_valid_signed_package` case in `formula/evaluation.js` simply forwards to this generic verifier, again with no automatic AA-address or context binding: [3](#0-2) 

Because there is no engine-enforced domain separator, the ocore/oscript documentation and sample templates (e.g. `test/samples/payment_channels.oscript`) explicitly instruct AA authors to *manually* embed a binding field such as `channel: this_address` inside `signed_message` and bounce if it doesn't match:
```
if (trigger.data.sentByPeer.signed_message.channel != this_address)
    bounce('signed for another channel');
``` [4](#0-3) 

This is the equivalent of the EIP-712 "recommended fix" being pushed entirely onto individual application authors instead of being enforced by the primitive itself. Any AA author who follows the more naive pattern used in `test/samples/order_book_exchange.oscript` — binding only on `address`, `sell_asset`, `buy_asset`, `sell_amount`, `price`, and `last_ball_unit`, but never on `this_address` (i.e. which specific market/exchange AA is authorized to consume the order) — produces off-chain signed orders that remain valid for **any** AA instance sharing the same field-naming convention and signer: [5](#0-4) 

### Impact Explanation
If a user signs an off-chain package (order, payment-channel state update, price attestation, etc.) intended for AA #1, and a second AA #2 is deployed using the same or a structurally-compatible template (a common practice, since users freely deploy AA definitions from shared templates/base addresses), an attacker (any unprivileged trigger sender) can resubmit the identical `signed_package` object as trigger data to AA #2. Because `is_valid_signed_package` has no concept of "this signature was only meant for AA #1," AA #2 will accept it as genuine, causing unauthorized state transitions: executing a stale/duplicate order, releasing AA-held funds, or accepting a stale balance/commitment update — i.e., AA fund loss or a double-spend of a signed commitment across instances. This satisfies the "AA fund loss or freezing" / "unauthorized spending" impact bar, provided a vulnerable AA (using naive signed-package binding) is deployed and reachable by trigger senders.

### Likelihood Explanation
Exploitability is contingent on an AA author's template failing to add explicit domain binding (e.g., `this_address`) inside `signed_message` — which the payment-channel sample in the repo itself does correctly, but the order-book sample does not fully (it never checks `this_address`, only order-specific fields tied to a `last_ball_unit`). Because ocore ships/document multiple templates and does not enforce domain separation at the engine level, the likelihood of at least one deployed AA being vulnerable is moderate-to-high; the flaw is a systemic design gap in the primitive rather than an isolated app bug, closely paralleling the original LGO finding.

### Recommendation
Have `is_valid_signed_package`/`getSignedPackageHashToSign` (or a stricter variant) require and hash-bind a mandatory domain-separation field — e.g., automatically fold in `this_address` (the calling AA) and/or an explicit `app`/`purpose` string into the hash-to-sign, similar to EIP-712's `DOMAIN_SEPARATOR` (chainId + verifying contract). At minimum, update the oscript documentation/linter to require every `signed_message` schema used with `is_valid_signed_package` to carry and verify a `this_address` (or equivalent) field, and add a static check in `formula/validation.js` warning when `is_valid_signed_package` is used without a corresponding check against `this_address` in the same branch.

### Proof of Concept
1. Deploy two AAs, `AA_A` and `AA_B`, both cloned from `test/samples/order_book_exchange.oscript` (or any template that verifies `is_valid_signed_package(order, order.address)` without checking `this_address`).
2. Alice signs an order package `{sell_asset, buy_asset, sell_amount, price, last_ball_unit}` intending to trade only on `AA_A`.
3. Bob captures this signed package (it is broadcast on-chain as trigger `data.order1` once used, or leaked off-chain) and submits it as trigger data to `AA_B`.
4. `AA_B` calls `is_valid_signed_package(trigger.data.order1, order1.address)` → `signed_message.validateSignedMessage()` → `getSignedPackageHashToSign()` [1](#0-0)  which validates successfully because nothing in the hash ties the package to `AA_A`.
5. `AA_B` executes the order against its own order book/balances, consuming Alice's signature and balance commitments in a context she never authorized — demonstrating cross-AA signature replay analogous to the LGO `permit()` replay.

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

**File:** signed_message.js (L255-288)
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

**File:** test/ojson.test.js (L1201-1210)
```javascript
							if: `{ trigger.data.fraud_proof AND var['close_initiated_by'] AND trigger.data.sentByPeer }`,
							init: `{
					$bInitiatedByA = (var['close_initiated_by'] == 'A');
					if (trigger.data.sentByPeer.signed_message.channel != this_address)
						bounce('signed for another channel');
					if (trigger.data.sentByPeer.signed_message.period != var['period'])
						bounce('signed for a different period of this channel');
					if (!is_valid_signed_package(trigger.data.sentByPeer, $bInitiatedByA ? $addressA : $addressB))
						bounce('invalid signature by peer');
					$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
```

**File:** test/samples/order_book_exchange.oscript (L27-49)
```text
			{ // execute orders, order1 must be smaller or the same as order2; order2 is partially filled
				if: `{
					$order1 = trigger.data.order1.signed_message;
					$order2 = trigger.data.order2.signed_message;
					if (!$order1.sell_asset OR !$order2.sell_asset)
						return false;
					if ($order1.sell_asset != $order2.buy_asset OR $order1.buy_asset != $order2.sell_asset)
						return false;

					// to do check expiry

					$sell_key1 = 'balance_' || $order1.address || '_' || $order1.sell_asset;
					$sell_key2 = 'balance_' || $order2.address || '_' || $order2.sell_asset;

					$id1 = sha256($order1.address || $order1.sell_asset || $order1.buy_asset || $order1.sell_amount || $order1.price || trigger.data.order1.last_ball_unit);
					$id2 = sha256($order2.address || $order2.sell_asset || $order2.buy_asset || $order2.sell_amount || $order2.price || trigger.data.order2.last_ball_unit);

					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;

					if (!is_valid_signed_package(trigger.data.order1, $order1.address)
						OR !is_valid_signed_package(trigger.data.order2, $order2.address))
						return false;
```
