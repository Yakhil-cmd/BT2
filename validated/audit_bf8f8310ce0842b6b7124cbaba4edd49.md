## Title
Improper Access Control via Signature "Wrapping" in Prosaic Contract Acceptance - (File: wallet.js, prosaic_contract.js)

### Summary
The `prosaic_contract_response` handler in `wallet.js` authenticates a contract-acceptance message solely by checking that the plaintext `signed_message` string equals the contract's `title` field, rather than verifying it against a value that cryptographically commits to the *entire* contract (text, creation date, amount/terms). This mirrors the CVE-2015-5253 "wrapping attack" pattern: a validly signed assertion (here, a signature over a bare title string) is accepted as proof of agreement to a materially different object (a different contract sharing the same title) that the signer never actually reviewed or signed.

### Finding Description
When a peer accepts a prosaic contract, `wallet.js`'s `prosaic_contract_response` case decodes `body.signed_message`, calls `signed_message.validateSignedMessage` to confirm the message is validly signed by `objContract.peer_address`, and then performs the sole content check: [1](#0-0) 

```
signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
    if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
```

The only binding between the cryptographic signature and the specific contract being accepted is equality of `objSignedMessage.signed_message` with `objContract.title` — a short, attacker/offeror-controlled free-text string. The actual contract identity is `getHash(contract)`, computed from `title + text + creation_date`: [2](#0-1) 

Because the signature only ever covers the `title` substring (not `text`, `creation_date`, or the contract `hash`), a validly-signed acceptance produced for one contract offer can be replayed and accepted as proof of agreement for any other contract record that happens to carry the same `title` but different `text`/`creation_date`/terms — a direct structural analog to the SAML wrapping attack, where a validly signed assertion element is detached from its original context and revalidated against a different, unprotected part of the message (here, the DB row `objContract` looked up only by `hash`, while the trust decision is keyed off the unprotected `title` field instead of the full signed content).

### Impact Explanation
`processResponse` on successful "acceptance" moves the contract to `status = "accepted"` and proceeds to derive/create the shared multisig address and drive fund deposit/escrow flow between the two devices: [3](#0-2) 

If an attacker (a legitimate device-message peer, i.e., a private-payment counterparty reachable without special privilege) can cause a stale or substitute "accepted" signature (over a shared `title`) to be matched against a different, unintended contract object, the offeror's wallet will treat the acceptance as valid consent to the terms of the wrong contract (different `text`, price, or `creation_date`/`ttl`), proceeding to establish a shared address and downstream payment flow based on unauthorized/forged consent to a specific agreement. This is an authorization bypass (CWE-284): the code trusts an insufficiently-bound assertion to authorize a materially different transaction context, matching the "concrete unauthorized spending"/counterparty fund-loss criteria via mismatched contract terms driving the deposit/escrow logic.

### Likelihood Explanation
This requires no privileged access — it is reachable by any device correspondent acting as the counterparty in an ongoing or prior prosaic-contract negotiation (an in-scope "private-payment counterparty"). The attack only requires two prosaic contracts to exist with an identical `title` (fully controlled by the offeror when composing the offer, and not otherwise constrained to be unique), which is easily engineered by the party controlling contract creation, or coincidentally by reusing common titles ("Invoice", "Payment", "Agreement") across independent negotiations with the same peer.

### Recommendation
Bind the signature verification to the full, unique contract identity rather than the mutable `title` field: require `objSignedMessage.signed_message === objContract.hash` (or a string that deterministically encodes `title + text + creation_date`, matching `getHash`), so acceptance can never be revalidated against any other contract record — closing the wrapping/substitution gap.

### Proof of Concept
1. Offeror creates contract A: `{title: "Invoice", text: "Pay 10 GBYTE for goods", creation_date: D1}` → `hash_A = getHash(A)`, sent to peer, stored `status=pending`.
2. Peer's device signs and returns `signed_message = "Invoice"` (equal to `title`) as acceptance of A, referencing `hash_A`; this is accepted per `wallet.js:569` because `signed_message == title`.
3. Later (or in a race), the same offeror (or an operator of the peer's own outgoing offers) creates contract B: `{title: "Invoice", text: "Pay 10000 GBYTE, no refunds", creation_date: D2}` → different `hash_B`, `status=pending`, sent to the same peer/device pairing.
4. A `prosaic_contract_response` message referencing `hash_B` but replaying/reusing the previously captured valid signature (`signed_message = "Invoice"`, `authors` array unchanged, still validly signed by `peer_address`) is delivered.
5. `signed_message.validateSignedMessage` succeeds (signature is cryptographically valid), and the check `objSignedMessage.signed_message != objContract.title` passes because both titles are `"Invoice"`. Contract B is marked `accepted`, and the wallet proceeds to derive the shared address and enter the deposit/escrow flow for terms the peer never actually reviewed or intended to sign.

### Citations

**File:** wallet.js (L548-556)
```javascript
						if (objContract.status !== 'pending')
							return callbacks.ifError("contract is not active, current status: " + objContract.status);
						var objDateCopy = new Date(objContract.creation_date_obj);
						if (objDateCopy.setHours(objDateCopy.getHours(), objDateCopy.getMinutes(), (objDateCopy.getSeconds() + objContract.ttl * 60 * 60)|0) < Date.now())
							return callbacks.ifError("contract already expired");
						prosaic_contract.setField(objContract.hash, "status", body.status);
						eventBus.emit("text", from_address, "contract \""+objContract.title+"\" " + body.status, ++message_counter);
						eventBus.emit("prosaic_contract_response_received" + body.hash, (body.status === "accepted"), body.authors);
						callbacks.ifOk();
```

**File:** wallet.js (L568-570)
```javascript
						signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
							if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
								return callbacks.ifError("wrong contract signature");
```

**File:** prosaic_contract.js (L98-104)
```javascript
function getHash(contract) {
	return crypto.createHash("sha256").update(contract.title + contract.text + contract.creation_date, "utf8").digest("base64");
}

function getHashV1(contract) {
	return objectHash.getBase64Hash(contract.title + contract.text + contract.creation_date);
}
```
