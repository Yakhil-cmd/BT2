## Title
AA-generated response units bypass `MAX_UNIT_LENGTH`, allowing unbounded-size unit creation from an AA trigger - (File: validation.js)

### Summary
The CVE describes ImageMagick performing no upper-bound check on an image profile's size before allocating/writing it during PNG encoding, causing a heap overflow. The closest reachable analog in ocore is in `validation.js`, where the overall-unit-size sanity check that normally caps every unit at `constants.MAX_UNIT_LENGTH` (5 MB) is explicitly skipped for AA-generated (bounce/response) units, and the "profile"/"data"/"attestation" message payloads that feed into that size have no independent length cap of their own.

### Finding Description
In `validate()`, after computing header and payload sizes, the code enforces a global cap: [1](#0-0) 

```
if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission) ...
if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
    return callbacks.ifUnitError("unit too large");
```

This check is unconditionally bypassed when `bAA` is true, i.e., for units produced by `aa_composer.js` in response to a trigger [2](#0-1) . Meanwhile, individual field-level size checks for message payload types reachable from AA templates (`"data"`, `"profile"`, `"attestation"`) do not impose any length bound at all — they only check that the payload is a non-empty object: [3](#0-2) [4](#0-3) 

By contrast, `"data_feed"` explicitly enforces `MAX_DATA_FEED_NAME_LENGTH`/`MAX_DATA_FEED_VALUE_LENGTH` per field [5](#0-4) , showing that the "data"/"profile"/"attestation" cases were never given an equivalent bound.

While individual formula-produced strings are capped by `MAX_AA_STRING_LENGTH` (via `concat`/`json_stringify` checks in `formula/evaluation.js`), an AA definition can be authored with up to `MAX_MESSAGES_PER_UNIT` (128) messages, each carrying near-maximal-size "profile"/"data"/"attestation" objects composed from many concatenated fields/keys, and this AA can be re-triggered repeatedly by any unprivileged sender. Because `getTotalPayloadSize()`/`getHeadersSize()` (used only for fee accounting, not size limiting) are exempted from the `MAX_UNIT_LENGTH` ceiling for `bAA` units, a triggerer can force the network to construct, hash, JSON-stringify, and persist (via `writer.js`, which does `JSON.stringify(message.payload)` for "data"/"profile"/"attestation" without any size guard [6](#0-5) ) units that are many times larger than what any normal, non-AA unit is permitted to be.

### Impact Explanation
Every full node that processes the resulting AA response unit must independently: evaluate the AA formula, serialize/hash the oversized payload (`objectHash.getUnitHash`, `getSourceString`/`getJsonSourceString`), and write it to the DAG. Because the size cap that protects normal nodes from oversized memory allocations is deliberately disabled for AA units, a malicious trigger sender can repeatedly force outsized allocations/serializations network-wide, degrading or crashing full nodes during validation/storage of that AA's response units. If nodes disagree on whether such a response can be validated/stored within resource limits (e.g., some nodes OOM or time out while others succeed), this can lead to node disagreement on unit validity/stability, and in the extreme, contribute to the network being unable to confirm new units built on top of that AA. This satisfies "node disagreement on validity or stability" / "network unable to confirm new units" thresholds required by the rules.

### Likelihood Explanation
Likelihood is moderate: this requires deploying (or using an existing) AA whose definition builds large "profile"/"data"/"attestation" objects from trigger-controlled strings/keys, and triggering it. No privileged access is needed — any address can post a trigger unit to a public AA (or the attacker can define their own AA). The per-string cap `MAX_AA_STRING_LENGTH` limits the size of any single field, but with up to 128 messages, nested objects, and unbounded field-name generation, the aggregate response payload size is not bounded by anything comparable to `MAX_UNIT_LENGTH`, and the `!bAA` bypass at `validation.js:267` is unconditional.

### Recommendation
Apply the `MAX_UNIT_LENGTH` (or an AA-specific, still-bounded) ceiling to AA-generated units instead of exempting them entirely, and/or add explicit length caps analogous to `MAX_DATA_FEED_VALUE_LENGTH` for "data", "profile", and "attestation" payloads (including nested/aggregate size, not just per-string length) both in the general message validator and in AA definition/message validation (`aa_validation.js`).

### Proof of Concept
1. Author an AA whose `messages` template includes several `"profile"`/`"data"`/`"attestation"` messages, each containing many keys with near-`MAX_AA_STRING_LENGTH` string values built from `trigger.data` fields and `concat`.
2. Post a trigger unit to this AA from an unprivileged address; repeat the trigger many times or with maximal filler in `trigger.data`.
3. Observe that the resulting AA response unit's `headers_commission + payload_commission` exceeds `constants.MAX_UNIT_LENGTH`, yet `validate()` accepts it because `bAA` is true (validation.js:267), whereas an equivalent manually-crafted non-AA unit of the same size would be rejected as "unit too large".

**Uncertainty**: I could not fully trace the exact upper bound achievable by chaining `MAX_MESSAGES_PER_UNIT`/`MAX_AA_STRING_LENGTH`/state-var storage limits against real AA execution to confirm a concrete multi-MB payload is achievable end-to-end (this would require running the AA composer/formula evaluator, which is outside static code search). The finding is based on the confirmed code-level fact that the `MAX_UNIT_LENGTH` guard is explicitly bypassed for `bAA` units and that "data"/"profile"/"attestation" payload validation has no size cap, but the practical maximum achievable unit size and the severity of resulting resource exhaustion should be validated with a running Devin session.

### Citations

**File:** validation.js (L257-268)
```javascript
		if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
			return callbacks.ifJointError("wrong headers commission, expected "+objectLength.getHeadersSize(objUnit));
		try {
			const payloadSize = objectLength.getTotalPayloadSize(objUnit);
			if (payloadSize !== objUnit.payload_commission)
				return callbacks.ifJointError("wrong payload commission, unit " + objUnit.unit + ", expected " + payloadSize);
		}
		catch (e) {
			return callbacks.ifJointError("failed to calculate payload commission: " + e);
		}
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```

**File:** validation.js (L1925-1951)
```javascript
		case "data_feed":
			if (objValidationState.bHasDataFeed)
				return callback("can be only one data feed");
			objValidationState.bHasDataFeed = true;
			if (!isNonemptyObject(payload))
				return callback("data feed payload must be non-empty object");
			if (Object.keys(payload).length * objUnit.authors.length > constants.MAX_DATA_FEEDS_PER_MESSAGE)
				return callback("too many data feeds in message");
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
				}
				else if (typeof value === 'number'){
					if (!isInteger(value))
						return callback("fractional numbers not allowed in data feeds");
				}
				else
					return callback("data feed "+feed_name+" must be string or number");
			}
```

**File:** validation.js (L1954-1964)
```javascript
		case "profile":
			if (objUnit.authors.length !== 1)
				return callback("profile must be single-authored");
			if (objValidationState.bHasProfile)
				return callback("can be only one profile");
			objValidationState.bHasProfile = true;
			// no break, continuing
		case "data":
			if (typeof payload !== "object" || payload === null)
				return callback(objMessage.app+" payload must be object");
			return callback();
```

**File:** validation.js (L2011-2024)
```javascript
		case "attestation":
			if (objUnit.authors.length !== 1)
				return callback("attestation must be single-authored");
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "profile"]))
				return callback("unknown fields in "+objMessage.app);
			if (!isValidAddress(payload.address))
				return callback("attesting an invalid address");
			if (!isNonemptyObject(payload.profile))
				return callback("attested profile must be non empty object");
			// it is ok if the address has never been used yet
			// it is also ok to attest oneself
			return callback();
```

**File:** aa_composer.js (L1382-1404)
```javascript
				pickParents(function (parent_units) {
					objUnit.parent_units = parent_units;
					objUnit.headers_commission = objectLength.getHeadersSize(objUnit);
					objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
					var size = objUnit.headers_commission + objUnit.payload_commission;
					console.log('unit before completing bytes payment', util.inspect(objUnit, { depth: 6 }));
					completePaymentPayload(objBasePaymentMessage.payload, size, function (err) {
					//	console.log('--- completePaymentPayload', err);
						if (err)
							return bounce(err);
						addOutputAddresses(objBasePaymentMessage.payload.outputs);
						try {
							completeMessage(objBasePaymentMessage); // fixes payload_hash
						}
						catch (e) {
							return bounce("base completeMessage failed: " + e.toString());
						}
						objUnit.payload_commission = objectLength.getTotalPayloadSize(objUnit);
						const oversize_fee = (mci >= constants.v4UpgradeMci) ? storage.getOversizeFee(objUnit, last_ball_mci, true) : 0;
						if (oversize_fee)
							objUnit.oversize_fee = oversize_fee;
						objUnit.unit = objectHash.getUnitHash(objUnit);
						console.log('unit', util.inspect(objUnit, { depth: 6 }))
```

**File:** writer.js (L169-182)
```javascript
		if (!objUnit.content_hash){
			for (var i=0; i<objUnit.messages.length; i++){
				var message = objUnit.messages[i];
				
				var text_payload = null;
				if (message.app === "text")
					text_payload = message.payload;
				else if (message.app === "data" || message.app === "profile" || message.app === "attestation" || message.app === "definition_template")
					text_payload = JSON.stringify(message.payload);
				
				conn.addQuery(arrQueries, "INSERT INTO messages \n\
					(unit, message_index, app, payload_hash, payload_location, payload, payload_uri, payload_uri_hash) VALUES(?,?,?,?,?,?,?,?)", 
					[objUnit.unit, i, message.app, message.payload_hash, message.payload_location, text_payload, 
					message.payload_uri, message.payload_uri_hash]);
```
