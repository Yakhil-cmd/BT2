### Title
`is_valid_signed_package()` / `signed_message.validateSignedMessage()` do not bind signatures to the consuming AA address, enabling cross-AA signature replay - (File: `signed_message.js`, `formula/evaluation.js`)

### Summary
The oscript primitive `is_valid_signed_package(signed_package, address)` (backed by `signed_message.validateSignedMessage()`) only proves that a given `address` signed a `signed_message` payload; it never binds the signature to the specific Autonomous Agent (AA) that is consuming it. Any binding to "this contract instance" must be manually added by the AA author inside the signed message content. This is the same root cause as the reported "safeAddress not included in signatures" bug: the signature/digest is scoped to the signer only, not to the specific "safe"/contract instance that is supposed to accept it, so a valid signature produced for one instance can be replayed against another instance that shares the same signer and the same signed-message schema.

### Finding Description
`is_valid_signed_package` in `formula/evaluation.js` evaluates the `address` argument and hands the raw `signedPackage` straight to `signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, ...)`: [1](#0-0) 

`validateSignedMessage` only checks that: the `authors` array is well-formed, the specified `address` appears among the authors, the definition hashes to that address, and the authentifiers verify against `getSignedPackageHashToSign(objSignedMessage)`: [2](#0-1) 

`getSignedPackageHashToSign` computes the hash over the naked package (`signed_message`, `authors` addresses, `version`, `last_ball_unit`) — it never includes the address of the AA that will interpret the message: [3](#0-2) 

Consequently, there is no protocol-level guarantee that a `signed_message` was produced *for* a particular AA instance. The framework's own sample code acknowledges this: the `payment_channels.oscript` template must manually add a `channel` field to the signed message and explicitly compare it to `this_address` before trusting the signature, precisely to prevent cross-channel/cross-instance replay: [4](#0-3) 

If an AA author omits this manual check (unlike the shipped sample), a counterparty's signature that was valid for one deployed instance of a template (e.g., payment channel, order-book contract, price-oracle consumer) can be replayed verbatim against another instance that expects signatures from the same address and uses the same `signed_message` field layout — exactly analogous to a Gnosis Safe signature being replayed across safes because `safeAddress` wasn't part of the digest.

### Impact Explanation
Any AA template that is instantiated multiple times (multiple payment channels with different peers/periods, multiple order-book/exchange AAs, multiple contracts relying on the same off-chain signer/oracle) and that fails to embed an explicit `this_address`/instance identifier inside the signed message is exposed to signature replay across instances. This can let a party close/settle a channel or trigger a payout in AA-B using a message that was only ever intended, authorized, and possibly nonce-checked for AA-A, resulting in direct fund loss or state corruption in the victim AA. This matches the "AA fund loss" impact class.

### Likelihood Explanation
Exploitation requires two independently deployed AA instances sharing the same message schema and same expected signer address, plus an AA author who does not add the "this address" binding manually - a real risk given the raw primitive provides no protection by default and only diligent template authors (as evidenced by the in-repo sample explicitly guarding against it) avoid the issue. Since the primitive is a general building block for many custom AAs (channels, escrows, oracles), the likelihood of misuse in third-party AA code is realistic even though ocore's own bundled samples are safe.

### Recommendation
Harden the primitive rather than relying purely on AA-author discipline: require (or optionally allow enforcing) that `signed_message` packages consumed via `is_valid_signed_package` include a reserved field bound to the consuming address (e.g., automatically verify `signed_message.address === address` or `=== this_address` when present, or extend `getSignedPackageHashToSign` to optionally take a `for_address`/domain parameter supplied by the AA at verification time and mixed into the digest). At minimum, update documentation/templates to make the `this_address` binding mandatory guidance, and consider emitting a warning/complexity note when `is_valid_signed_package` is used without any reference to `this_address` in the same branch.

### Proof of Concept
1. Deploy two instances of the same AA template (e.g., a payment-channel-like bot) at different addresses `AA1` and `AA2`, both configured to accept signed packages from the same peer address `P` and both consuming a `signed_message` schema identical to `{ period, amount_spent }` with no instance/channel identifier field, i.e. omit the guard used in `test/samples/payment_channels.oscript` lines 107-108 (`if (trigger.data.sentByPeer.signed_message.channel != this_address) bounce(...)`).
2. Peer `P` signs a package authorizing a settlement/payout for `AA1` via `signMessage`/wallet "sign" flow producing `objSignedMessage` per `signed_message.js` `signMessage()`.
3. Attacker (who is the trigger-sender, possibly the AA's counterparty) posts a trigger unit to `AA2` embedding the exact same `signedPackage` obtained from step 2 in `trigger.data.sentByPeer`.
4. `AA2`'s formula calls `is_valid_signed_package(trigger.data.sentByPeer, P)`, which succeeds because `validateSignedMessage` only checks the signature against `P` and message freshness (`last_ball_unit`), not which AA the message was meant for.
5. `AA2` executes the payout/settlement logic intended for `AA1`, causing fund loss/freezing in `AA2` or duplicate spend of funds that were only supposed to move once.

### Citations

**File:** formula/evaluation.js (L1659-1699)
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
```

**File:** signed_message.js (L257-296)
```javascript
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

**File:** test/samples/payment_channels.oscript (L104-112)
```text
				if: `{ trigger.data.fraud_proof AND var['close_initiated_by'] AND trigger.data.sentByPeer }`,
				init: `{
					$bInitiatedByA = (var['close_initiated_by'] == 'A');
					if (trigger.data.sentByPeer.signed_message.channel != this_address)
						bounce('signed for another channel');
					if (trigger.data.sentByPeer.signed_message.period != var['period'])
						bounce('signed for a different period of this channel');
					if (!is_valid_signed_package(trigger.data.sentByPeer, $bInitiatedByA ? $addressA : $addressB))
						bounce('invalid signature by peer');
```
