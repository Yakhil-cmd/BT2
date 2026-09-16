## Title
Weak signature binding in arbiter/prosaic contract acceptance allows victim's signed acceptance to be replayed against a different contract with the same title - (File: wallet.js)

### Summary
The bug-class hint from the ParaSpace report describes a signature that is valid for a "credit" object which lacks a marketplace identifier, so a maker's signature intended for one bid/order can be replayed against an unrelated, worthless order in a different context. The analogous weakness in `ocore` is in the `arbiter_contract_response` / `prosaic_contract_response` P2P handlers in `wallet.js`, where a peer's acceptance of a contract is authenticated by comparing a generic, attacker-controlled `signed_message` field to the free-text `title` of the contract rather than to a full, unique hash of the contract's binding terms.

### Finding Description
When a party accepts an arbiter or prosaic contract, the acceptance is authenticated via `signed_message.validateSignedMessage`, and the *content* that must match is just the contract's `title` string: [1](#0-0) [2](#0-1) 

The `title` field is a free-text, user-supplied string (up to 1000 characters), completely independent of the contract's binding economic terms (`amount`, `asset`, `peer_address`, `arbiter_address`, `text`, `creation_date`, `me_is_payer`), as seen in the DB schema and `getHashSrc`: [3](#0-2) [4](#0-3) 

`validateSignedMessage` itself only verifies that the given address really signed the string content; it has no knowledge of, and no binding to, the specific contract (`hash`), amount, asset, or counterparty of the transaction it is meant to authorize: [5](#0-4) 

The acceptance-processing code checks only that `objSignedMessage.signed_message` equals `objContract.title`, and that the signer address matches `objContract.peer_address`: [6](#0-5) [7](#0-6) 

There is no check that the signed message binds to `objContract.hash` (which is the only field that uniquely commits to the full set of contract terms). This mirrors exactly the ParaSpace `Credit` struct bug: a signature over generic, reusable content ("title" here, "orderId"-less structure there) lacking a strong identifier binding it to one specific transaction context.

### Impact Explanation
Because the signed content is only the human-readable `title`, an attacker (the contract offeror) can:
1. Send contract offer A to the victim with `title = "Invoice #1"`, `amount = 1`, low-value terms, and get the victim to sign acceptance (signing `"Invoice #1"`).
2. Separately (or simultaneously) send/re-send/replay a second `arbiter_contract_offer`/`prosaic_contract_offer` (contract B) with the *same* `title = "Invoice #1"` but a much larger `amount`, different `asset`, or different `peer_address`/`arbiter_address`. Because contracts are keyed and matched only by `hash` (which the attacker fully controls, since they craft the offer) and stored independently, the attacker can present the victim's previously obtained signed message (`"Invoice #1"`) as the acceptance for contract B.
3. `validateSignedMessage` only validates that the signer authored the string `"Invoice #1"` — it has no way to detect that this signature was originally produced for a different set of contract terms. The check `objSignedMessage.signed_message != objContract.title` passes for contract B, and the victim's device processes it as a valid, binding "accepted" response, moving the contract to `accepted` status and driving forward creation of the shared multisig address and the arbiter-secured payment flow bound to the attacker's terms in contract B, not the ones the victim actually reviewed and intended to accept.

This can result in the victim being bound to (and funding) a shared-address arbiter contract with terms (amount, asset, counterparty) they never actually agreed to, i.e., unauthorized/fraudulent commitment of funds through a spoofed acceptance — a concrete fund-loss/fund-freezing scenario reachable by any unprivileged private-payment counterparty (the contract offeror) against the victim they're directly conversing with.

### Likelihood Explanation
Likelihood is Medium: it requires the attacker to control the contract offer (trivial, since they are the counterparty proposing arbiter/prosaic contracts) and to induce the victim to accept an initial low-stakes-looking offer whose title text they later reuse for a high-stakes offer. Because `title` is arbitrary text chosen by the offeror and not shown to the user with any cryptographic linkage to `hash`/`amount` at signing time beyond the UI display, a crafted duplicate-title attack is straightforward for a determined counterparty and does not require any protocol violation, malicious hub, or network-level attack — it only requires abuse of the existing wallet contract-acceptance flow.

### Recommendation
Bind the signed acceptance message to the full contract commitment rather than to the free-text `title`. Concretely, change the acceptance signature payload (and the corresponding check in `wallet.js`) to require `objSignedMessage.signed_message === objContract.hash` (the hash already binds `title`, `text`, `creation_date`, `payer/payee` addresses, `arbiter_address`, `amount`, and `asset`, per `getHashSrc`), instead of comparing to `objContract.title`. Apply the analogous fix to `prosaic_contract_response` handling as well, and audit any other use of `signed_message`/`is_valid_signed_package` in wallet/contract flows for the same "compare to a non-unique, weakly-bound field" pattern.

### Proof of Concept
1. Attacker (device D) sends `arbiter_contract_offer` to victim with `title="Invoice #1"`, small `amount=1`, `asset=null` (bytes), `arbiter_address=X`.
2. Victim reviews and accepts; wallet computes `signed_message = signMessage("Invoice #1", ...)` and sends `arbiter_contract_response` with `status="accepted"` and the base64-encoded signed package.
3. Victim's device validates and stores this per `wallet.js:617-940` flow; the acceptance for contract A is recorded.
4. Attacker now crafts a second `arbiter_contract_offer` (contract B) with the identical `title="Invoice #1"` but `amount=100000`, different `asset`/`peer_address` fields as the attacker wishes, obtaining a distinct `hash` (per `getHash`), and sends it to the victim (or simply already has one queued via `arbiter_contract_shared`/multi-device flow).
5. Attacker replays the base64 `signed_message` obtained in step 2 as the `signed_message` in an `arbiter_contract_response` claiming acceptance of contract B.
6. In `wallet.js:932-935`, `signed_message.validateSignedMessage` succeeds (the signature over `"Invoice #1"` is valid and signer matches `objContract.peer_address`), and `objSignedMessage.signed_message == objContract.title` (`"Invoice #1" == "Invoice #1"`) passes, so contract B is marked `accepted` even though the victim never reviewed or intended to accept its actual (larger/different) terms.

### Citations

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

**File:** arbiter_contract.js (L194-207)
```javascript
function getHashSrc(contract) {
	const payer_name = contract.me_is_payer ? contract.my_party_name : contract.peer_party_name;
	const payee_name = contract.me_is_payer ? contract.peer_party_name : contract.my_party_name;
	const payer_address = contract.me_is_payer ? contract.my_address : contract.peer_address;
	const payee_address = contract.me_is_payer ? contract.peer_address : contract.my_address;
	const src = contract.creation_date > exports.NEW_HASH_DATE
		 ? [contract.title, contract.text, contract.creation_date, payer_address, payer_name || '', contract.arbiter_address, payee_address, payee_name || '', contract.amount, contract.asset || 'null'].join(exports.DELIMITER)
		 : [contract.title, contract.text, contract.creation_date, payer_name || '', contract.arbiter_address, payee_name || '', contract.amount, contract.asset || 'null'].join("");
	return src;
}

function getHash(contract) {
	return crypto.createHash("sha256").update(getHashSrc(contract), "utf8").digest("base64");
}
```

**File:** initial-db/byteball-sqlite.sql (L891-921)
```sql
CREATE TABLE IF NOT EXISTS wallet_arbiter_contracts (
	hash CHAR(44) NOT NULL PRIMARY KEY,
	peer_address CHAR(32) NOT NULL,
	peer_device_address CHAR(33) NOT NULL,
	my_address  CHAR(32) NOT NULL,
	arbiter_address CHAR(32) NOT NULL,
	me_is_payer TINYINT NOT NULL,
	my_party_name VARCHAR(100) NULL,
	peer_party_name VARCHAR(100) NULL,
	amount BIGINT NULL,
	asset CHAR(44) NULL,
	is_incoming TINYINT NOT NULL,
	me_is_cosigner TINYINT NULL,
	creation_date TIMESTAMP NOT NULL,
	ttl INT NOT NULL DEFAULT 168, -- 168 hours = 24 * 7 = 1 week \n\
	status VARCHAR(40) CHECK (status IN('pending', 'revoked', 'accepted', 'signed', 'declined', 'paid', 'in_dispute', 'dispute_resolved', 'in_appeal', 'appeal_approved', 'appeal_declined', 'cancelled', 'completed')) NOT NULL DEFAULT 'pending',
	title VARCHAR(1000) NOT NULL,
	text TEXT NOT NULL,
	my_contact_info TEXT NULL,
	peer_contact_info TEXT NULL,
	my_pairing_code VARCHAR(200) NULL,
	peer_pairing_code VARCHAR(200) NULL,
	shared_address CHAR(32) NULL UNIQUE,
	unit CHAR(44) NULL,
	cosigners VARCHAR(1500),
	resolution_unit CHAR(44) NULL,
	arbstore_address  CHAR(32) NULL,
	arbstore_device_address  CHAR(33) NULL,
	FOREIGN KEY (shared_address) REFERENCES shared_addresses(shared_address),
	FOREIGN KEY (my_address) REFERENCES my_addresses(address)
);
```

**File:** signed_message.js (L117-196)
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
	var authors = objSignedMessage.authors;
	if (!ValidationUtils.isNonemptyArray(authors))
		return handleResult("no authors");
	if (!address && !ValidationUtils.isArrayOfLength(authors, 1))
		return handleResult("authors not an array of len 1");
	if (authors.length > constants.MAX_AUTHORS_PER_UNIT)
		return handleResult("too many authors");
	var prev_address = "";
	var the_author;
	for (var i = 0; i < authors.length; i++){
		var author = authors[i];
		if (!ValidationUtils.isNonemptyObject(author))
			return handleResult("author must be a non-empty object");
		if (!ValidationUtils.isValidAddress(author.address))
			return handleResult("not valid address");
		if (author.address <= prev_address)
			return handleResult("author addresses not sorted");
		prev_address = author.address;
		if (ValidationUtils.hasFieldsExcept(author, ['address', 'definition', 'authentifiers']))
			return handleResult("foreign fields in author");
		if ("definition" in author) {
			if (!ValidationUtils.isArrayOfLength(author.definition, 2))
				return handleResult("definition must be an array of length 2");
			if (author.definition[0] === 'autonomous agent')
				return handleResult('AA cannot be defined in authors');
			try {
				if (objectHash.getChash160(author.definition) !== author.address)
					return handleResult("wrong definition: " + objectHash.getChash160(author.definition) + "!==" + author.address);
			}
			catch (e) {
				return handleResult("failed to calc address definition hash: " + e);
			}
		}
		if (author.address === address)
			the_author = author;
		if (!ValidationUtils.isNonemptyObject(author.authentifiers))
			return handleResult("no authentifiers");
		for (let path in author.authentifiers) {
			if (!ValidationUtils.isNonemptyString(author.authentifiers[path]))
				return handleResult("authentifiers must be nonempty strings");
			if (author.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return handleResult("authentifier too long");
		}
	}
	if (!the_author) {
		if (address)
			return handleResult("not signed by the expected address");
		the_author = authors[0];
	}
	try { // check for nulls and empty objects, this makes getChash160 safe on all authors, not just the signer
		string_utils.getJsonSourceString(objSignedMessage);
	}
	catch (e) {
		return handleResult("invalid signed message: " + e);
	}
	var bNetworkAware = ("last_ball_unit" in objSignedMessage);
	if (bNetworkAware && !ValidationUtils.isValidBase64(objSignedMessage.last_ball_unit, constants.HASH_LENGTH))
		return handleResult("invalid last_ball_unit");
	
```
