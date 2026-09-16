### Title
Authentication/Integrity Bypass via Type Juggling in Signed Contract-Response Validation - (File: wallet.js)

### Summary
`wallet.js` validates peer responses to prosaic and arbiter contracts by comparing the cryptographically-signed `signed_message` field against the locally stored contract `title` using the loose inequality operator `!=` instead of a strict, type-checked comparison. Because `signed_message.js` never constrains the *type* of the `signed_message` field (it only checks that the key exists), a remote pairing counterparty can sign an arbitrary non-string JSON value (number, boolean, array, etc.) that JavaScript's abstract-equality algorithm coerces into being "equal" to the contract's string title, even though the literal, actually-signed content is different. This is the same bug class as CVE-2023-53894 (phpfm): security-relevant equality is decided with a loosely-typed comparison operator, allowing an attacker who fully controls one operand's type to force a false-positive match.

### Finding Description
The `signed_message` field accepted from a device-paired peer is validated in `signed_message.js`: [1](#0-0) 

Note that `hasFieldsExcept` and the "in" check only ensure the key is present — no `typeof` restriction (e.g. `isNonemptyString`) is applied to `objSignedMessage.signed_message` itself. Its value can therefore be a number, boolean, array, object, or `null`, and this value gets cryptographically signed and hashed via `getSignedPackageHashToSign`/`validateAuthentifiers`, so the *signature* is fully valid for whatever type/value the peer chose.

After signature validation succeeds, `wallet.js` performs the security-critical business check with `!=` (loose): [2](#0-1) 

The same pattern recurs for arbiter contracts: [3](#0-2) 

Since `objContract.title` is always a string read from the local database, and `objSignedMessage.signed_message` can be forced to virtually any JSON primitive by the remote peer, an attacker can pick a value whose JS-coerced comparison to the title string returns `false` (i.e., "not different") without the value actually matching the title. Examples of `!=` returning false despite mismatched literal content: a numeric-looking title `"0"` vs signed value `0` (number); an empty title `""` vs signed value `false` or `0`; etc. In all such cases the peer's genuine ECDSA signature covers the coerced value, not the string title, yet the wallet logic treats it as if the peer explicitly signed off on that title.

### Impact Explanation
This check gatekeeps whether a wallet accepts a peer's `accepted`/`declined` response for a prosaic or arbiter contract as genuinely tied to the specific contract text. Arbiter contracts (`arbiter_contract.js`) underlie shared-address escrow payment flows and later dispute resolution (`arbiter_dispute_request`), where the contract's hashed text is used to compute payment/mutual-signing conditions and drive fund release decisions. A pairing counterparty exploiting this type-juggling gap can make the local wallet record a forged "acceptance" tied to a title string it never literally signed, corrupting the record used to validate later dispute/arbitration steps and potentially causing the AA/escrow logic to treat the contract as validly accepted when it was not, leading to fund loss or a dispute the honest party cannot correctly evidence.

### Likelihood Explanation
The bug is reachable by any paired device / private-payment counterparty simply by sending a crafted `prosaic_contract_response` or `arbiter_contract_response` device message with `body.signed_message` containing a base64-encoded JSON object whose `signed_message` field is a non-string value. No special privileges beyond normal device pairing (already a modeled actor in scope) are required, and producing a valid signature over an attacker-chosen value is trivial since the attacker signs with their own key over their own chosen content.

### Recommendation
Enforce `ValidationUtils.isNonemptyString(objSignedMessage.signed_message)` (or an explicit allowed-type check appropriate to the use case) in `signed_message.js`'s `validateSignedMessage`, and replace all business-logic comparisons of `signed_message` content against expected strings (`wallet.js` lines ~569 and ~933) with strict `!==`/`===` comparisons after confirming both operands are strings.

### Proof of Concept
1. Attacker (Bob) is paired with Victim (Alice) and receives a `prosaic_contract_offer` with `title: "0"`.
2. Bob crafts a `signed_message` package: `{ signed_message: 0, authors: [{ address: Bob_address, definition: [...], authentifiers: {...} }] }`, signs it with his own key (valid signature over the number `0`, not the string `"0"`).
3. Bob base64-encodes this JSON and sends `prosaic_contract_response` with `status: "accepted"`, `hash: <contract hash>`, `signed_message: <base64>`.
4. `signed_message.validateSignedMessage` succeeds because `signed_message` field is present and the signature over value `0` is cryptographically valid; there is no type check rejecting a numeric `signed_message`.
5. `wallet.js` executes `objSignedMessage.signed_message != objContract.title` → `0 != "0"` → `false`, so the mismatch check is skipped and the response is processed as if Bob genuinely signed the literal title string `"0"`. [4](#0-3) [5](#0-4)

### Citations

**File:** signed_message.js (L130-137)
```javascript
	if (!ValidationUtils.isNonemptyObject(objSignedMessage))
		return handleResult("signed message must be a non-empty object");
	if (ValidationUtils.hasFieldsExcept(objSignedMessage, ["signed_message", "authors", "last_ball_unit", "timestamp", "version"]))
		return handleResult("unknown fields");
	if (!('signed_message' in objSignedMessage))
		return handleResult("no signed message");
	if ("version" in objSignedMessage && constants.supported_versions.indexOf(objSignedMessage.version) === -1)
		return handleResult("unsupported version: " + JSON.stringify(objSignedMessage.version));
```

**File:** wallet.js (L558-571)
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
```

**File:** wallet.js (L924-935)
```javascript
					if (body.signed_message) {
						try{
							var signedMessageJson = Buffer.from(body.signed_message, 'base64').toString('utf8');
							var objSignedMessage = JSON.parse(signedMessageJson);
						}
						catch(e){
							return callbacks.ifError("wrong signed message");
						}
						signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
							if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
								return callbacks.ifError("wrong contract signature");
							processResponse(objSignedMessage);
```
