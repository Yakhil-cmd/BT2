## Analog Found

### Title
Prosaic-contract acceptance signature binds only the contract title, not its text/terms — unprotected content is not indicated as such - (File: `wallet.js`)

### Summary
CVE‑2021‑29957 is about a client trusting a cryptographically protected fragment of a message while treating an adjacent, unprotected fragment as if it were equally protected. The `prosaic_contract_response` handler in ocore has the same defect: it verifies the peer's `signed_message` authentifier only against `objContract.title`, while the actual contractual terms (`text`, `creation_date`) that constitute the real "content" of the agreement are never bound to the signature that is checked here.

### Finding Description
When a device receives a `prosaic_contract_response`, the code decodes the peer‑supplied `signed_message`, validates the signature cryptographically, and then checks equality against the contract: [1](#0-0) 

```
signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
    if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
        return callbacks.ifError("wrong contract signature");
    processResponse(objSignedMessage);
});
```

`validateSignedMessage` (in `signed_message.js`) correctly verifies that the `signed_message` field itself is cryptographically signed by the claimed author, using `getSignedPackageHashToSign` over the whole `objSignedMessage` object: [2](#0-1) [3](#0-2) 

However, the *content* that the caller checks the signature against is `objContract.title` only — `objContract.text`, `objContract.creation_date`, `amount`, and `asset`, which together make up the real contractual obligation and were themselves committed to at offer time via `getHash(contract)` (`title + text + creation_date`) — are never part of the signed payload that is validated here: [4](#0-3) 

So the peer's signature genuinely protects only the `title` string; the rest of the contract that the local device believes was "accepted" (`text`, terms, amount encoded in the text) is effectively unprotected in this acceptance step, exactly like a MIME email where the inline-signed part covers only a fragment while the rest is silently treated as verified.

### Impact Explanation
Because the acceptance check binds only the `title`, a counterparty (an unprivileged, already-paired "private-payment counterparty", squarely in scope) can produce or reuse one signed acceptance for any contract sharing the same `title` string irrespective of `text`/terms/amount. If an offeror ever creates multiple contract offers to the same peer with an identical `title` but different `text` (e.g., different payment amount or condition), a single peer‑signed acceptance is valid to mark *any* of those pending contracts as `accepted`: [5](#0-4) 

The local device treats `status = accepted` as proof the peer reviewed and agreed to the full displayed terms, then proceeds to derive the shared address and permit fund deposit/claim flows for that contract: [6](#0-5) 

This can lead to the offeror funding/committing to terms the peer never actually cryptographically agreed to, i.e., a fund-loss / spending-authorization confusion rooted in an incomplete signature-coverage check, which the rules classify as in-scope ("wallet and contract message handling", "private-payment counterparty").

### Likelihood Explanation
Exploitation requires the attacker to be the paired contract peer (already an authorized, unprivileged counterparty in the payment negotiation), and requires the victim offeror to have two or more pending contracts to the same peer sharing an identical title but different text — a realistic pattern for recurring/templated agreements (e.g., "Invoice", "Rent", "Escrow"). No hub/node compromise or additional privilege is needed, only crafting a normal `prosaic_contract_response` message, so likelihood is moderate.

### Recommendation
Bind the acceptance signature to the full contract commitment rather than just the title — e.g., require `objSignedMessage.signed_message === objContract.hash` (which already commits to `title + text + creation_date`) instead of comparing to `objContract.title`, so that any unprotected field cannot diverge from what was actually signed.

### Proof of Concept
1. Offeror device sends two `prosaic_contract_offer` messages to the same peer with identical `title` ("Invoice") but different `text` (e.g., contract A: pay 100; contract B: pay 100000), each producing a distinct `hash` since `getHash` includes `text`.
2. The peer accepts contract A honestly, producing `signed_message.signed_message = "Invoice"` signed by their key, sent back with `hash = hashA`, `status = "accepted"`.
3. Because the wallet.js check only verifies `objSignedMessage.signed_message != objContract.title`, this acceptance payload — with `hash` field swapped to `hashB` — is accepted for contract B as well, marking it `accepted` even though the peer's signature never referenced `text` (i.e., the 100000 terms of contract B), fulfilling the "unprotected part not indicated" bug class. [7](#0-6) [1](#0-0)

### Citations

**File:** wallet.js (L504-518)
```javascript
			case 'prosaic_contract_response':
				if (!ValidationUtils.isNonemptyString(body.hash))
					return callbacks.ifError("no contract hash");
				if (body.status !== "accepted" && body.status !== "declined")
					return callbacks.ifError("wrong status supplied");

				prosaic_contract.getByHash(body.hash, function(objContract){
					if (!objContract)
						return callbacks.ifError("wrong contract hash");
					if (body.status === "accepted" && !body.signed_message)
						return callbacks.ifError("response is not signed");
					if (from_address !== objContract.peer_device_address)
						return callbacks.ifError("response is from wrong device");
					if (objContract.is_incoming)
						return callbacks.ifError("this contract is incoming, you cannot accept your own offer");
```

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

**File:** wallet.js (L558-572)
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
						});
```

**File:** wallet.js (L2044-2062)
```javascript
					async.series([function(cb) { // step 1: prosaic/arbiter contract shared address deposit
						var payment_msg = _.find(objUnsignedUnit.messages, function(m){return m.app=="payment" && m.payload && !m.payload.asset});
						if (!payment_msg)
							return cb();
						var possible_contract_output = _.find(payment_msg.payload.outputs, function(o){return o.amount==prosaic_contract.CHARGE_AMOUNT || o.amount==arbiter_contract.CHARGE_AMOUNT});
						if (!possible_contract_output)
							return cb();
						var table = possible_contract_output.amount==prosaic_contract.CHARGE_AMOUNT ? 'prosaic' : 'wallet_arbiter';
						db.query("SELECT peer_device_address FROM "+table+"_contracts WHERE shared_address=?", [possible_contract_output.address], function(rows) {
							if (!rows.length)
								return cb();
							if (!bRequestedConfirmation) {
								if (rows[0].peer_device_address !== device_address)
									eventBus.emit("confirm_contract_deposit");
								bRequestedConfirmation = true;
							}
							return cb(true);
						});
					}, function(cb) { // step 2: posting unit with contract hash (or not a prosaic and arbiter contract / not a tx at all)
```

**File:** signed_message.js (L117-135)
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
```

**File:** signed_message.js (L255-276)
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
