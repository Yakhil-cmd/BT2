### Title
Unvalidated `data_length`/`data_hash` in AA-generated `temp_data` messages allows fee-forging and permanently unverifiable data commitments - ([File: validation.js])

### Summary
The CVE describes libpq trusting a server-supplied, unbounded length value to fill a caller buffer without validating it against real data (`PQfn(..., result_is_int=0, ...)`), which lets a hostile counterpart drive client-side buffer corruption. The `ocore` analog is `validateInlinePayload()`'s handling of `app: "temp_data"` messages: the `data_length`/`data_hash` fields, which directly drive fee accounting (`objectLength.getTempDataLength` / `getTotalPayloadSize`), are only cross-checked against the real `data` blob when `data` is actually present in the payload. When an AA response message omits `data` (`objValidationState.bAA` is true), the code skips the real-data existence/consistency check entirely, so an AA author can commit to arbitrary `data_length`/`data_hash` values that never correspond to any real payload.

### Finding Description
In `validation.js`, the `temp_data` case is: [1](#0-0) 

- `data_length` is only range-checked as a positive integer (`isPositiveInteger`), with no upper bound and no correlation to real content unless `data` is inline.
- When `"data" in payload` is true, the code recomputes `objectLength.getLength(payload.data, true)` and `objectHash.getBase64Hash(payload.data, true)` and compares them to the claimed `data_length`/`data_hash` — this is the real defense.
- When `"data" in payload` is false, the `else` branch only performs a transient "not found yet" check, and explicitly **excludes AA responses**: `... && !objValidationState.bAA`. So for AA-generated `temp_data` messages, there is no verification step at all that a `data_length`/`data_hash` pair corresponds to any real, retrievable data — ever.

This value then feeds fee/commission computation used by every validating node: [2](#0-1) [3](#0-2) 

`getTotalPayloadSize()` (used to check `payload_commission` in `validation.js`) and `getPaidTempDataFee()` both trust `payload.data_length` verbatim: [4](#0-3) 

Because AA definitions are only checked for generic message shape (`isNonemptyObject(payload)`) at definition-validation time, not at response-generation time: [5](#0-4) 

an AA author can craft a formula that emits a `temp_data` message carrying only `{data_length, data_hash}` (no `data`), with `data_length` set to an arbitrary large (or small) constant/formula result and `data_hash` set to any syntactically valid base64 string, and this passes validation unconditionally for AA responses.

### Impact Explanation
`data_length` is the sole and only input used to compute `temp_data_length` and hence `payload_commission` / `TEMP_DATA_PRICE` fee for the response unit — money that is deducted from the triggering AA's own balance/bounce fee accounting in `aa_composer.js`. Because this value is deterministic to all validating full nodes (they all just trust the field, none can independently verify it since the real bytes never existed), there is no consensus split, but:
- A malicious or buggy public AA can make an arbitrarily large "phantom" `data_length` claim to inflate its own `payload_commission`, unexpectedly draining/freezing AA balance funds on every trigger that reaches this code path (denial of funds/AA fund loss), or conversely under-declare it to reduce fees paid relative to actual network resource commitments the mechanism was designed to enforce.
- The resulting unit permanently commits an unverifiable `data_hash`/`data_length` claim (no real "gets()"-style unbounded write here since this is JS, but the same trust-without-verification root cause), breaking the temp_data integrity contract that every other producer of this app (human-authored units) is forced to honor via the strict `data`-present branch.

This satisfies the "AA fund loss or freezing" impact category without touching malicious-peer/network-only concerns — the trigger is a normal AA response generated during ordinary DAG validation, reachable by any unprivileged user who triggers a vulnerable/malicious public AA.

### Likelihood Explanation
Any AA author can add a `temp_data` message to their AA's response definition without ever populating the `data` field, and any user triggering that AA will have this path exercised during standard AA execution and subsequent unit validation by every full node. No special network position, hub compromise, or privileged access is needed — only posting a trigger to a deployed AA whose definition contains such a message.

### Recommendation
Enforce the same integrity requirements for AA-generated `temp_data` messages as for human-authored ones: either require AAs to always emit the actual `data` field (so the existing `getLength`/hash cross-check in `validation.js:1979-1995` applies), or add an explicit upper bound plus a mandatory verification step (e.g., requiring the AA composer to compute `data_length`/`data_hash` internally from real, composer-controlled data rather than allowing arbitrary formula-driven values to be injected uncontrolled into `payload.data_length`/`payload.data_hash` when `bAA` is true).

### Proof of Concept
1. Deploy an AA whose response definition includes a message:
```
{
  app: 'temp_data',
  payload: {
    data_length: 100000000,     // arbitrary, unrelated to any real data
    data_hash: '<any syntactically valid 44-char base64 hash>'
  }
}
```
2. Trigger the AA with any unprivileged unit.
3. In `aa_composer.js`, the response message is generated without a `data` field.
4. In `validation.js`, `validateInlinePayload()` reaches the `temp_data` case; since `objValidationState.bAA === true`, the `else` branch's real-data existence/consistency check is bypassed (`&& !objValidationState.bAA` short-circuits it) — no error is raised despite `data_length`/`data_hash` never corresponding to real content.
5. `objectLength.getTempDataLength()`/`getTotalPayloadSize()` compute `payload_commission` directly from the fabricated `data_length`, silently charging (or under-charging) the AA's balance for data that was never produced and can never be retrieved.

### Citations

**File:** validation.js (L257-266)
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
```

**File:** validation.js (L1966-2001)
```javascript
		case "temp_data":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci)
				return callback("cannot use temp_data yet");
			if (typeof payload !== "object" || payload === null)
				return callback("temp_data payload must be an object");
			if (Array.isArray(payload))
				return callback("temp_data payload must not be an array");
			if (hasFieldsExcept(payload, ["data_length", "data_hash", "data"]))
				return callback("unknown fields in " + objMessage.app);
			if (!isPositiveInteger(payload.data_length))
				return callback("bad data_length");
			if (!isValidBase64(payload.data_hash))
				return callback("bad data_hash");
			if ("data" in payload) {
				const createError = objValidationState.bAA ? err => err : createJointError;
				if (payload.data === null)
					return callback(createError("null data"));
				if (!payload.data && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return callback(createError("falsy temp data: " + payload.data)); // getTotalPayloadSize() checks for thruthiness
				try {
					const len = objectLength.getLength(payload.data, true);
					if (len !== payload.data_length)
						return callback(createError(`data_length mismatch, expected ${payload.data_length}, got ${len}`));
					const hash = objectHash.getBase64Hash(payload.data, true);
					if (hash !== payload.data_hash)
						return callback(createError(`data_hash mismatch, expected ${payload.data_hash}, got ${hash}`));
				}
				catch (e) {
					return callback(createError("invalid temp data: " + e));
				}
			}
			else {
				if (Math.round(Date.now()/1000) - objUnit.timestamp < constants.TEMP_DATA_PURGE_TIMEOUT && !objValidationState.bAA)
					return callback(createTransientError("data not found in temp_data"))
			}
			return callback();
```

**File:** object_length.js (L79-96)
```javascript
function extractTempData(messages) {
	let temp_data_length = 0;
	let messages_without_temp_data = messages;
	for (let i = 0; i < messages.length; i++) {
		const m = messages[i];
		if (m.app === "temp_data") {
			if (!m.payload || typeof m.payload.data_length !== "number") // invalid message, but we don't want to throw exceptions here, so just ignore, and validation will fail later
				continue;
			temp_data_length += m.payload.data_length + 4; // "data".length is 4
			if (m.payload.data) {
				if (messages_without_temp_data === messages) // not copied yet
					messages_without_temp_data = _.cloneDeep(messages);
				delete messages_without_temp_data[i].payload.data;
			}
		}
	}
	return { temp_data_length, messages_without_temp_data };
}
```

**File:** object_length.js (L98-112)
```javascript
function getTempDataLength(objUnit) {
	let temp_data_length = 0;
	for (let m of objUnit.messages){
		if (m.app === "temp_data") {
			if (!m.payload || typeof m.payload.data_length !== "number") // invalid message, but we don't want to throw exceptions here, so just ignore, and validation will fail later
				continue;
			temp_data_length += m.payload.data_length + 4; // "data".length is 4
		}
	}
	return temp_data_length;
}

function getPaidTempDataFee(objUnit) {
	return Math.ceil(getTempDataLength(objUnit) * constants.TEMP_DATA_PRICE);
}
```

**File:** aa_validation.js (L83-90)
```javascript
			switch (message.app) {
				case 'profile':
				case 'data':
				case 'temp_data':
					if (!isNonemptyObject(payload))
						return cb2('payload of app=' + message.app + ' must be non-empty object or formula: ' + JSON.stringify(payload));
					cb2();
					break;
```
