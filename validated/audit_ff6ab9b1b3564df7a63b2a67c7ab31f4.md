### Title
Missing content-hash verification for URI-referenced message payloads allows unverified/substitutable payload data - (File: validation.js)

### Summary
`validation.js` supports messages whose payload is not carried inline but referenced by a URL (`payload_location: "uri"`). The unit only binds cryptographically to the *URL string* (`payload_uri_hash`) and separately declares an arbitrary `payload_hash`, but ocore never fetches the URI and never checks that the content actually retrieved from it hashes to `payload_hash`. This mirrors the ZeroBrew class of bug: a manifest/unit commits to a *location* pointer and a claimed *checksum*, but nothing in the validated code path ever fetches the resource and verifies the checksum against the retrieved bytes, so whoever controls the URL (the poster, a MITM, or a compromised host) can serve arbitrary, unverifiable content while the unit itself validates as fully well-formed.

### Finding Description
In `validateMessage()`, when `objMessage.payload_location === "uri"`, the following checks are performed: [1](#0-0) 
- `payload_uri` must be a trimmed string ≤500 chars with no null bytes.
- `payload_uri_hash` must equal `objectHash.getBase64Hash(objMessage.payload_uri)` — i.e., the hash of the **URL text**, not of the resource it points to.
- Separately, every message (including `uri`-located ones) must carry a `payload_hash` of the declared correct length, checked only for well-formedness: [2](#0-1) 
```
function validatePayload(cb){
    if (objMessage.payload_location === "inline"){
        validateInlinePayload(...);
    }
    else{
        if (!isValidBase64(objMessage.payload_hash, constants.HASH_LENGTH))
            return cb("wrong payload hash");
        cb();
    }
}
```
For `payload_location !== "inline"` (which includes `"uri"`), the code merely checks that `payload_hash` is base64 of the right *length* — it never fetches `payload_uri` and never verifies that the fetched bytes hash to `payload_hash`. Compare this to the `inline` path (and to `hasValidPayloadHashes()`), where `payload_hash` is always recomputed from the actual payload and strictly enforced: [3](#0-2) [4](#0-3) 

The DB schema confirms `payload_uri`, `payload_uri_hash`, and `payload_hash` are all stored as independent, unrelated fields with no foreign linkage enforced by the storage layer either: [5](#0-4) 

`uri.js` contains a generic `fetchUrl()` helper used elsewhere in the wallet/light-client tooling to retrieve remote content by URL: [6](#0-5) 
Nothing in the reachable validation or storage code ever calls such a fetch-and-verify routine for `payload_location: "uri"` messages to confirm that content at `payload_uri` matches `payload_hash`. As a result, `payload_hash` for URI-located messages is a purely decorative, self-declared value that the unit's author controls and that is never checked against anything — the equivalent of ZeroBrew's shim trusting a URL/patch reference without validating the fetched bytes against any checksum.

### Impact Explanation
Any unprivileged unit poster can attach a message with `payload_location: "uri"` to a fully valid, otherwise well-formed unit. The unit passes all consensus validation (unit hash, payload_uri_hash-of-URL-string, payload_hash length check) with no verification that content at the URL matches any claimed digest. Any downstream consumer of this unit (wallets, hubs, or other software built on ocore that dereferences `payload_uri` and trusts the co-located `payload_hash` as an integrity guarantee, exactly as the ZeroBrew shim trusted resource/patch URLs) can be served attacker-swapped content post-hoc, since:
- the URL can point to attacker/second-party-controlled infrastructure that can change its response at any time after the unit becomes stable,
- `payload_hash` provides zero binding to the actual bytes returned,
- nodes/wallets have no mechanism in ocore itself to detect the substitution, because the "hash" that is checked (`payload_uri_hash`) covers only the literal URL string, not the resource.
This does not directly forge a payment or double-spend by itself, but it undermines the core promise that a unit's referenced payload is immutable and verifiable — the same integrity-verification gap class as CVE-2026-53970, applied to on-chain URI payload references instead of package resource URLs.

### Likelihood Explanation
High reachability: any address holder can post a unit with a `uri` message referencing an arbitrary attacker-controlled URL, with no special privilege, node compromise, or witness/hub cooperation required. The gap has existed since payload_location "uri" was introduced and is not conditioned on any upgrade MCI or feature flag, so it is exploitable on any current network today.

### Recommendation
Either (a) remove `payload_hash` from `uri`-located messages entirely if it is not meant to be an integrity check (avoiding the false impression of security), or (b) if consumers are expected to treat it as a genuine content-integrity commitment, document/enforce that any code fetching `payload_uri` MUST verify the retrieved bytes hash to `payload_hash` before use, and add defensive checks to any first-party ocore fetch helper (e.g., extend `uri.js`'s `fetchUrl`) to compute and compare the hash automatically rather than leaving verification implicit and easy to skip.

### Proof of Concept
1. Attacker composes a unit with a message: `{ app: "text", payload_location: "uri", payload_uri: "https://attacker.example/data.json", payload_uri_hash: getBase64Hash("https://attacker.example/data.json"), payload_hash: <any well-formed 44-char base64 string> }`.
2. Unit passes `validateMessage()`/`validateInlinePayload()` bypass path because `payload_location !== "inline"` only checks `payload_hash` length, not content.
3. Unit is broadcast, validated, and becomes stable — all consensus nodes accept it without ever fetching `https://attacker.example/data.json`.
4. Attacker's server initially serves benign content matching whatever a downstream client checked at first sight, then swaps the response to malicious content later; because `payload_hash` was never bound to real content, the swap is undetectable by ocore's own protocol layer, and any client that dereferences the URI and trusts `payload_hash` as-is is misled about data integrity.

### Citations

**File:** validation.js (L55-73)
```javascript
function hasValidPayloadHashes(objJoint) {
	try {
		if (!("messages" in objJoint.unit)) return true; // final-bad
		if (!isNonemptyArray(objJoint.unit.messages)) return false;
		for (let m of objJoint.unit.messages) {
			if (m.payload_location !== "inline") {
				if ("payload" in m)
					return false;
				continue;
			}
			const expected_payload_hash = objectHash.getBase64Hash(getPayloadForHash(m), objJoint.unit.version !== constants.versionWithoutTimestamp);
			if (expected_payload_hash !== m.payload_hash)
				return false;
			if (m.app === "temp_data" && "data" in m.payload) {
				const hash = objectHash.getBase64Hash(m.payload.data, true);
				if (hash !== m.payload.data_hash)
					return false;
			}
		}
```

**File:** validation.js (L219-243)
```javascript
		// validate payload hashes early to make sure payloads were not tampered with
		for (let m of objUnit.messages) {
			if (typeof m.payload_location !== "string")
				return callbacks.ifUnitError("bad payload_location");
			if (!["inline", "none", "uri"].includes(m.payload_location))
				return callbacks.ifUnitError("invalid payload_location: " + m.payload_location);
			if (!isStringOfLength(m.payload_hash, constants.HASH_LENGTH))
				return callbacks.ifUnitError("wrong payload hash size");
			if (m.payload_location !== "inline") {
				if ("payload" in m)
					return callbacks.ifJointError("payload must be absent when payload_location is not inline");
				continue;
			};
			if (!("payload" in m) || m.payload === null)
				return callbacks.ifJointError("missing payload");
			
			try {
				const expected_payload_hash = objectHash.getBase64Hash(getPayloadForHash(m), objUnit.version !== constants.versionWithoutTimestamp);
				if (expected_payload_hash !== m.payload_hash)
					return callbacks.ifJointError("wrong payload hash: expected " + expected_payload_hash + ", got " + m.payload_hash);
			}
			catch(e) {
				return callbacks.ifJointError("failed to calc payload hash: " + e);
			}
		}
```

**File:** validation.js (L1590-1605)
```javascript
	if (objMessage.payload_location === "uri"){
		if ("payload" in objMessage)
			return callback(createJointError("must not contain payload"));
		if (typeof objMessage.payload_uri !== "string")
			return callback(createJointError("no payload uri"));
		if (objMessage.payload_uri !== objMessage.payload_uri.trim())
			return callback(createJointError("payload uri must be trimmed"));
		if (!isStringOfLength(objMessage.payload_uri_hash, constants.HASH_LENGTH))
			return callback("wrong length of payload uri hash");
		if (objMessage.payload_uri.length > 500)
			return callback(createJointError("payload_uri too long"));
		if (objMessage.payload_uri.includes("\x00"))
			return callback(createJointError("payload_uri contains null byte"));
		if (objectHash.getBase64Hash(objMessage.payload_uri) !== objMessage.payload_uri_hash)
			return callback(createJointError("wrong payload_uri hash"));
	}
```

**File:** validation.js (L1632-1641)
```javascript
	function validatePayload(cb){
		if (objMessage.payload_location === "inline"){
			validateInlinePayload(conn, objMessage, message_index, objUnit, objValidationState, cb);
		}
		else{
			if (!isValidBase64(objMessage.payload_hash, constants.HASH_LENGTH))
				return cb("wrong payload hash");
			cb();
		}
	}
```

**File:** initial-db/byteball-mysql.sql (L142-153)
```sql
CREATE TABLE messages (
	unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	message_index TINYINT NOT NULL,
	app VARCHAR(30) NOT NULL,
	payload_location ENUM('inline','uri','none') NOT NULL,
	payload_hash CHAR(44) NOT NULL,
	payload LONGTEXT NULL,
	payload_uri_hash CHAR(44) NULL,
	payload_uri VARCHAR(500) NULL,
	PRIMARY KEY (unit, message_index),
	FOREIGN KEY (unit) REFERENCES units(unit)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```

**File:** uri.js (L251-291)
```javascript
function fetchUrl(url, cb) {
	var https = require('https');
	var bDone = false;
	function returnError(err) {
		console.log(err);
		if (bDone)
			return;
		bDone = true;
		cb(err);
	}
	try {
		https.get(url, function (resp) {
			if (resp.statusCode !== 200)
				return returnError("non-200 response while trying to fetch " + url);
			var data = '';

			// A chunk of data has been recieved.
			resp.on('data', function(chunk) {
				data += chunk;
			});

			// aborted before the whole response has been received
			resp.on('aborted', function () {
				returnError("connection aborted while trying to fetch " + url);
			});

			// The whole response has been received
			resp.on('end', function () {
				if (bDone)
					return;
				bDone = true;
				cb(null, data);
			});
		}).on("error", function(err) {
			returnError("non-200 response while trying to fetch " + url + ": " + err.message);
		});
	}
	catch(err) {
		returnError(err.message);
	}
}
```
