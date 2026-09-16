Based on my investigation, I found a genuine structural analog in ocore's `signed_message.js`, used by the `is_valid_signed_package()` oscript function that AAs rely on to accept off-chain authorizations (e.g., payment-channel or order-book counterparty signatures) as "permits."

### Title
Off-chain signed messages ("permits") cannot be invalidated after an address rotates its definition - ([File: signed_message.js])

### Summary
`validateSignedMessage()` in [1](#0-0)  verifies a `signed_message` package (the eBTC-permit analog: a bearer credential that authorizes an action on behalf of an address, consumed by AAs through `is_valid_signed_package()`). When the package is not network-aware (no `last_ball_unit` field), the verifier does not check the address's *current* on-chain definition at all — it only checks that the definition embedded in the message hashes to the claimed address, then verifies the signature against that embedded definition.

### Finding Description
In the non-network-aware branch of `validateOrReadDefinition()`: [2](#0-1) 
the code requires `objAuthor.definition` to be present, checks `getChash160(objAuthor.definition) === objAuthor.address`, and then calls back with that definition — with no query against `address_definition_changes` or `storage.readDefinitionByAddress`. This is the same code path exercised by `is_valid_signed_package()`, which AA authors use as an authorization/permit mechanism (see `test/samples/payment_channels.oscript` lines 41-50 and `order_book_exchange.oscript`) to accept a counterparty's off-chain signature as proof of authorized state transfer.

Compare this to the network-aware branch, which does look up the current on-chain definition via `storage.readDefinitionByAddress`: [3](#0-2) 

Because the non-network-aware path trusts whatever definition is embedded in the signed package (as long as it hashes to the address), an address owner who signs a message once (e.g., authorizing a spend amount in a payment channel) has no way to invalidate that specific signed package later. Rotating keys via an `address_definition_change` unit does not help, because the verifier for `is_valid_signed_package()` never consults the current/updated definition — it accepts the old one bundled inside the previously-issued signed package. This directly mirrors the eBTC/BorrowerOperations report: a `_deadline`-bounded or approval-based authorization that, once issued, cannot be revoked by later on-chain state changes, because the verification path re-derives trust from data supplied by the presenter rather than from current on-chain state.

### Impact Explanation
Any AA design (payment channels, order-book/escrow style AAs) that relies on `is_valid_signed_package()` to authorize fund release based on a counterparty-supplied signed package is exposed: a party who received a signed authorization from the counterparty at an earlier "period"/state can hold onto it and later replay it even if the signer has since rotated keys attempting to invalidate stale credentials, because the AA-side check inherits `signed_message.js`'s behavior of trusting the embedded definition rather than the address's live definition. Where the AA's own state machine (period counters, nonces) does not perfectly bind every replay path, this can lead to unauthorized fund movement from the AA — an analog of unauthorized spending via un-revocable permits.

### Likelihood Explanation
Exploitability depends on the specific AA's use of `is_valid_signed_package()`; well-written templates (like the `payment_channels.oscript` sample) mitigate this with an explicit `period` field checked against `var['period']` in AA state. However, the underlying primitive itself — `signed_message.js`'s non-network-aware verification — provides no default protection, so any AA author who omits an application-level nonce/expiry (relying instead on key rotation to invalidate old signed packages, as the eBTC report's authors initially assumed permits worked) is silently vulnerable. This is a reachable, unprivileged-AA-trigger-sender-class issue since any user can submit a `trigger.data` containing an old signed package to an AA.

### Recommendation
Document explicitly (and ideally enforce at the `is_valid_signed_package()`/`signed_message.js` level) that non-network-aware signed messages are bearer credentials with no built-in revocation, and that AA authors must implement their own nonce/period/expiry state to invalidate previously issued signed packages — analogous to the `increaseNonce()`/`increasePermitNonce()` fix adopted for eBTC. Consider adding an optional current-definition check (network-aware mode) as the recommended default pattern in ocore's official AA templates and documentation.

### Proof of Concept
1. Address `A` signs a `signed_message` (via `signMessage()` in non-network-aware mode) granting counterparty `B` an authorization, e.g., `{signed_message: {channel: AA_address, period: 1, amount_spent: X}}`, without `last_ball_unit`.
2. `A` later determines this authorization should be revoked (e.g., rotates the address definition/keys, or simply wants to disable it).
3. `B` still holds the original signed package and its embedded `author.definition`.
4. `B` submits a trigger to the AA (or calls `is_valid_signed_package()` in any oscript context) referencing the stale signed package; `validateSignedMessage()`/`Definition.validateAuthentifiers()` validate it purely against the embedded definition and signature — it succeeds regardless of `A`'s subsequent definition change, because [2](#0-1)  never consults `address_definition_changes`.
5. If the consuming AA does not independently track a nonce/period matching the current authorization state, `B` can act on the stale, supposedly-revoked permit. [1](#0-0) [4](#0-3)

### Citations

**File:** signed_message.js (L117-128)
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
```

**File:** signed_message.js (L219-238)
```javascript
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
```

**File:** signed_message.js (L241-252)
```javascript
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
```

**File:** test/samples/payment_channels.oscript (L41-50)
```text
								if (trigger.data.sentByPeer.signed_message.channel != this_address)
									bounce('signed for another channel');
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
								$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
								if ($transferredFromPeer < 0)
									bounce('bad amount spent by peer: ' || $transferredFromPeer);
							}
```
