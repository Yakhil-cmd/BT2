## Title
Wallet contract acceptance signature is bound only to `title`, not the unique contract `hash` - ([File: wallet.js])

### Summary
`prosaic_contract_response` and `arbiter_contract_response` handlers in `wallet.js` accept a peer's `signed_message` as proof of contract acceptance, but the code only checks that the signed text equals `objContract.title` and that the signer address equals `objContract.peer_address` — it never checks that the signature covers the contract's unique `hash` (which is derived from `title + text + creation_date`, see `prosaic_contract.js` `getHash()`/`getHashV1()` and `arbiter_contract.js` `getHash()`).

### Finding Description
In `wallet.js` the acceptance flow for both prosaic and arbiter contracts does: [1](#0-0) [2](#0-1) 

```
signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
    if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
        return callbacks.ifError("wrong contract signature");
    processResponse(objSignedMessage);
});
```

This mirrors exactly the class of bug in the external report: a cryptographically valid signature is accepted as proof of a specific action (`removeFor` a key from a `fid` / accepting *this* contract) while the signed payload does not uniquely bind to the specific resource it is meant to authorize (the `fid` / the specific contract `hash`). Here the signed payload is only the free-text `title` string, and `title` is user-supplied and not guaranteed unique per peer. Two different contracts (differing in `text`/`creation_date`/`amount`, and therefore differing `hash`) between the same two parties can have an identical `title`. `validateSignedMessage` (in `signed_message.js`) only checks the ECDSA signature validity for the given address, definition, and message content — it has no concept of contract hash, so it cannot detect this collision.

### Impact Explanation
If a device once legitimately signed an acceptance message for a low-stakes/test contract with a given title, that exact `signed_message` (base64 signature blob) can be replayed by the sender of a new "arbiter_contract_response"/"prosaic_contract_response" message for any other pending contract from the same peer that happens to share the same title. Because the wallet's server code checks only `title` equality and peer address, not the contract-specific `hash`, the check `objSignedMessage.signed_message != objContract.title` will pass even though the user never intended to accept the second (potentially much larger-value, or additional cosigner) contract. This can lead to a contract being marked `accepted`/proceeding to shared-address creation and fund commitment without the counterparty's genuine consent for that specific contract, i.e., unauthorized commitment of funds analogous to the unauthorized key removal in the source report.

### Likelihood Explanation
Exploitation requires a malicious or careless counterparty to control (or induce) the creation of two contracts with an identical `title` under their own `peer_device_address`, and to have obtained (from a legitimate earlier exchange) a validly signed acceptance for that title. Since `title` is a free-text field entirely controlled by the contract-creating party, an attacker can trivially engineer the collision (e.g., reuse a title from a previous cheap/test contract when creating a costly one). This does not require breaking any cryptography — it only requires exploiting an insufficiently specific signed payload, exactly as in the source finding.

### Recommendation
Include the full contract `hash` (or at minimum `title + text + creation_date`, matching the actual `getHash()`/`getHashV1()` computation) in the signed message payload, and validate that the received `objSignedMessage.signed_message` equals `objContract.hash` (not just `objContract.title`) before accepting the response as valid.

### Proof of Concept
1. Alice and Bob pair devices. Bob offers Alice a contract C1 with `title = "Service Agreement"`, `text = "test terms"`, low `amount`.
2. Alice accepts C1: her device calls `respond()`/`signMessage()` producing a `signed_message` over the string `"Service Agreement"`, sent back to Bob as `prosaic_contract_response`/`arbiter_contract_response` with `status: "accepted"`.
3. Later, Bob creates a new contract C2 with the *same* `title = "Service Agreement"` but different `text`/`amount` (a real, high-value contract), and stores it as `pending`.
3. Bob (acting maliciously, or a MITM on the hub relaying messages) resends Alice's earlier `signed_message` blob attached to a `arbiter_contract_response`/`prosaic_contract_response` message referencing C2's `hash`.
4. In `wallet.js`, `signed_message.validateSignedMessage` succeeds (signature is valid for Alice's address and message text), and the check `objSignedMessage.signed_message != objContract.title` passes because both contracts share the title "Service Agreement". C2 gets marked `accepted` even though Alice never approved its actual terms/amount. [3](#0-2) [4](#0-3)

### Citations

**File:** wallet.js (L568-572)
```javascript
						signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
							if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
								return callbacks.ifError("wrong contract signature");
							processResponse(objSignedMessage);
						});
```

**File:** wallet.js (L924-936)
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
						});
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
