### Title
Unsigned `status` field lets a peer forge acceptance/decline of an arbiter contract offer whose signature only covers the title - ([File: wallet.js])

### Summary
The `hub/message` handler for the `arbiter_contract_response` subject verifies a `signed_message` only against `objContract.title`, while the `status` field ("accepted" or "declined") that actually drives contract state transitions and downstream fund-related logic is transmitted unsigned, alongside the signed package.

### Finding Description
When device A receives an `arbiter_contract_response` justsaying from its paired peer, the code validates the optional `body.signed_message` with `signed_message.validateSignedMessage`, checking only that `objSignedMessage.signed_message != objContract.title` and that the signer address matches `objContract.peer_address`. The `body.status` value ("accepted"/"declined") that is used to transition `objContract.status` and trigger `arbiter_contract_response_received` is read directly from the plaintext justsaying body and is never included in, or bound to, the signed hash. [1](#0-0) [2](#0-1) [3](#0-2) 

This mirrors the Ambire bug pattern exactly: a signature is created to authenticate one specific "mode" of an action (recover vs. cancel; here, acceptance vs. decline of a contract, both keyed to the same `title`), but a separate flag that flips the meaning of the signed content (`SIGMODE_CANCEL` vs. the recover mode / here `status`) is excluded from the hash that is actually verified: `objectHash.getSignedPackageHashToSign(objSignedMessage)` only hashes `signed_message`, `authors`, `last_ball_unit`, `version` fields — not any status/mode discriminator. [4](#0-3) [5](#0-4) 

Because the hub relays `hub/message` payloads and the justsaying handler trusts `body` fields outside the signed envelope, a malicious hub or a compromised relay path (or a peer replaying an old signed acceptance of the same contract title) can pair an old/legitimately-signed message (`signed_message: objContract.title`) with an attacker-chosen `status` value, since `body.status` is never bound into what is cryptographically checked.

### Impact Explanation
This can misrepresent a counterparty's genuine decision on a payment contract (e.g., turn a "declined" into an "accepted" contract, or vice versa), causing wallet-side state (`arbiter_contract_response_received`) to fire incorrectly and potentially trigger fund-related actions tied to contract acceptance in the arbiter/prosaic contract flow. This falls into "wallet and contract message handling" per the allowed analog classes.

### Likelihood Explanation
Exploitability requires control of message content between the `hub/message` relay and the peer (a malicious/compromising hub in the delivery path, or a peer that can resend/relay a previously signed `signed_message` with a different `status`). This is meaningfully constrained versus the fully unauthenticated Ambire scenario, and I could not fully verify from the available index whether `objContract.title` is unique per accept/decline exchange or reused across renegotiations, nor the exact downstream consequences of `arbiter_contract_response_received` in `arbiter_contract.js` (fund movement vs. UI/state only), since `arbiter_contract.js`'s full contents were not indexed in this pass.

### Recommendation
Include the `status` value inside the signed content (e.g., sign `title + "\n" + status` or add `status` as an explicit field of the `signed_message` payload validated by `validateSignedMessage`) so that a given signature cannot be reinterpreted under a different `status`.

### Proof of Concept
Not fully constructible from indexed context: the exact fields of `arbiter_contract` records (in particular whether `title` alone is a sufficiently unique/session-bound token across the contract's negotiation lifecycle) live in `arbiter_contract.js`, whose full body was not available in the code index for this session. A background Devin session with full repository access would be needed to confirm the exact state machine and construct a concrete forged-status PoC.

### Citations

**File:** wallet.js (L865-877)
```javascript
			case 'arbiter_contract_response':
				if (!ValidationUtils.isNonemptyString(body.hash))
					return callbacks.ifError("no contract hash");
				if (body.status !== "accepted" && body.status !== "declined")
					return callbacks.ifError("wrong status supplied");

				arbiter_contract.getByHash(body.hash, function(objContract){
					if (!objContract)
						return callbacks.ifError("wrong contract hash");
					if (body.status === "accepted" && !body.signed_message)
						return callbacks.ifError("response is not signed");
					if (from_address !== objContract.peer_device_address)
						return callbacks.ifError("response is from wrong device");
```

**File:** wallet.js (L909-922)
```javascript
						var isAllowed = objContract.status === "pending" || (objContract.status === 'accepted' && body.status === 'accepted');
						if (!isAllowed)
							return callbacks.ifError("contract is not active, current status: " + objContract.status);
						var objDateCopy = new Date(objContract.creation_date_obj);
						if (objDateCopy.setHours(objDateCopy.getHours(), objDateCopy.getMinutes(), (objDateCopy.getSeconds() + objContract.ttl * 60 * 60)|0) < Date.now())
							return callbacks.ifError("contract already expired");
						if (body.my_pairing_code && typeof body.my_pairing_code === 'string')
							arbiter_contract.setField(objContract.hash, "peer_pairing_code", body.my_pairing_code);
						if (body.my_contact_info && typeof body.my_contact_info === 'string')
							arbiter_contract.setField(objContract.hash, "peer_contact_info", body.my_contact_info);
						arbiter_contract.setField(objContract.hash, "status", body.status, function(objContract){
							eventBus.emit("arbiter_contract_response_received", objContract);
						});
						callbacks.ifOk();
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
