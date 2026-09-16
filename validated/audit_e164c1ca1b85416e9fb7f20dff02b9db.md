### Title
`is_valid_signed_package()` / `validateSignedMessage()` accepts a `timestamp` field but never validates it, and enforces no audience binding beyond the signer address - ([File: signed_message.js])

### Summary
The SAML advisory describes a validator (`ResponseProcessor.parse()`) that accepts an assertion and checks the signature but ignores the `Conditions` element — `NotBefore`, `NotOnOrAfter`, and `AudienceRestriction` — allowing expired assertions to be replayed and assertions meant for a different service provider to be accepted. `signed_message.js`'s `validateSignedMessage()` has the same structural gap: it fully verifies signatures/definitions of a `signed_message` package, but the optional `timestamp` field is accepted in the schema and never checked against current time or the referenced `last_ball_unit` timestamp, and there is no framework-level "audience" field binding the package to a specific consumer (AA address, channel, session, etc.).

### Finding Description
`validateSignedMessage()` whitelists `["signed_message", "authors", "last_ball_unit", "timestamp", "version"]` as allowed top-level fields [1](#0-0) , meaning a caller may include a `timestamp` in the signed package. However, nowhere in the function is `objSignedMessage.timestamp` read, compared to `Date.now()`, or checked against `last_ball_timestamp`/`last_ball_mci` for expiry [2](#0-1) . The only "freshness" signal used is `last_ball_unit`, which merely proves the package was created *after* a certain point in the DAG (a floor, analogous to `NotBefore`) — there is no corresponding upper bound (`NotOnOrAfter`) check anywhere, so once a package is valid it can be replayed indefinitely.

This validator is exposed directly to AA logic via `is_valid_signed_package()` in `formula/evaluation.js`, which is reachable by any AA trigger sender who crafts `trigger.data`. The evaluator verifies the package structure, an optional `last_ball_unit` stability check, and then calls `signed_message.validateSignedMessage()`, but performs no expiry/audience check of its own either [3](#0-2) .

Crucially, there is no built-in "audience" concept (equivalent to SAML's `AudienceRestriction`) restricting which AA, channel, or purpose a signed package may be used for. The framework relies entirely on the AA author manually embedding and checking binding fields inside `signed_message` (e.g. `channel` and `period` in the payment-channel sample) [4](#0-3) . If an AA author omits such manual binding/freshness checks (which is easy to do, since `is_valid_signed_package()` only validates cryptographic correctness), a signed package legitimately produced for one context/time can be replayed by a trigger sender in a different call, a different AA, or an arbitrarily later time, because the framework provides no default expiration or audience enforcement.

### Impact Explanation
Because the trigger sender fully controls `trigger.data` posted to an AA, and `is_valid_signed_package()`/`validateSignedMessage()` do not enforce expiry or audience restriction, any AA relying on off-chain "authorized signed messages" for state transitions (balance transfers, closes, approvals, price attestations, etc.) is exposed to replay of stale signed data unless the AA author independently re-implements freshness/binding logic. This can result in stale/incorrect AA state transitions, disputed fund releases based on outdated signed data, or acceptance of a signed package intended for a different AA/context — directly mirroring the SAML impact class (replay of expired assertions, cross-audience acceptance), translated to AA fund logic where it can cause fund loss or freezing depending on how an AA uses the primitive.

### Likelihood Explanation
Medium. Exploitation requires an AA whose oscript uses `is_valid_signed_package()`/off-chain signed messages without independently embedding freshness (e.g., a nonce, deadline, or `last_ball_unit` recency bound) and without a strict audience-binding field. The official sample (`payment_channels.oscript`) shows the *correct* mitigating pattern (checking `channel` and `period` inside the signed message), indicating AA authors are expected to build this protection themselves — but the ocore primitive itself provides no default protection, no documented "must expire" contract, and silently accepts (but ignores) a `timestamp` field that looks like it should provide exactly this protection.

### Recommendation
- Actively validate `objSignedMessage.timestamp` in `validateSignedMessage()` against a caller-supplied max-age / expiry, or document explicitly that it is unused so implementers don't mistakenly rely on it.
- Add an optional but enforced upper-bound freshness check in `is_valid_signed_package()` (e.g., require `last_ball_mci`/`last_ball_timestamp` to be within a caller-specified window, or accept an explicit `NotOnOrAfter`-style parameter that the runtime checks).
- Add first-class "audience" support to signed packages (e.g., an `audience`/`context` field that the framework validates against the invoking AA's address) so AA authors are not required to hand-roll audience binding, reducing the chance that an AA forgets to do so.

### Proof of Concept
1. AA author writes an oscript that accepts a peer-signed `trigger.data.sentByPeer` package for an approval/payout action, validating it only via `is_valid_signed_package(trigger.data.sentByPeer, peer_address)` without embedding any nonce, deadline, or unique per-use context field in `signed_message`.
2. Peer signs a message once (e.g., "I authorize releasing X funds") and sends it to the counterparty for a specific use.
3. The counterparty (trigger sender) submits it once to the AA and it's processed as intended.
4. The trigger sender resubmits the exact same signed package (unit hash for authentifiers is over `signed_message`/`authors`/`last_ball_unit`, not tied to a single use) in a second trigger, or reuses it against a *different* AA that also calls `is_valid_signed_package()` with the same address — both succeed because `validateSignedMessage()` never checks the ignored `timestamp` field nor any audience binding, only the cryptographic validity of the signature and (optionally) that `last_ball_unit` is stable and not before it.
5. Result: the same authorization is accepted twice / in an unintended context, an outcome the AA author did not anticipate because the framework offers no default protection against it.

Note: I was unable to find any test or code path elsewhere in the indexed codebase that reads `signedPackage.timestamp` for validation purposes, so I could not confirm whether this is intentionally deferred entirely to application code or an oversight; a full-repo grep for all consumers of `signed_message.js` would need to be done with direct file/terminal access to be exhaustive.

### Citations

**File:** signed_message.js (L132-133)
```javascript
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
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

**File:** test/samples/payment_channels.oscript (L104-118)
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
					$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
					if ($transferredFromPeer < 0)
						bounce('bad amount spent by peer: ' || $transferredFromPeer);
					$transferredFromPeerAsClaimedByPeer = var['spentBy' || ($bInitiatedByA ? 'A' : 'B')];
					if ($transferredFromPeer <= $transferredFromPeerAsClaimedByPeer)
						bounce("the peer didn't lie in his favor");
```
