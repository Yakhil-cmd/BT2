### Title
Unbounded `temp_data.data_length` enables floating-point precision loss in fee/commission arithmetic - (File: object_length.js)

### Summary
The `temp_data` message payload field `data_length` is validated only with `isPositiveInteger()`, which enforces "is a finite JS integer > 0" but has **no upper bound**. That length is later fed into unchecked arithmetic (`+ 4`) to compute the byte-commission a unit must pay, mirroring the NFSD bug class where an attacker-controlled length is used in downstream arithmetic before the value is range-checked. In this codebase JS numbers are IEEE-754 doubles, so the "overflow" surface is precision loss/inconsistency around `Number.MAX_SAFE_INTEGER` (2^53) rather than a 32-bit wrap, but the effect is the same: a single unprivileged unit author can supply a length value that is never checked against real content and is used directly in commission math.

### Finding Description
`temp_data` payload validation: [1](#0-0) 

Key points:
- `data_length` is only checked via `isPositiveInteger(payload.data_length)`, i.e. `Number.isInteger(x) && x > 0` — no maximum: [2](#0-1) 
- The length is cross-checked against real data **only when `"data" in payload`**: [3](#0-2) 
- If `data` is absent and the unit timestamp is old enough (`Date.now()/1000 - objUnit.timestamp >= constants.TEMP_DATA_PURGE_TIMEOUT`) or the message comes from an AA response, validation accepts the message **without ever checking the real length of the data** — `data_length` is trusted as-is: [4](#0-3) 
- The trusted, attacker-supplied `data_length` is then summed with a constant and used to compute payload size / fee, with no bound and no overflow-safety: [5](#0-4) 
- That aggregate feeds directly into `objUnit.payload_commission`, which is compared for equality against the unit's self-declared field: [6](#0-5) 

Because `data_length` can be set arbitrarily close to `Number.MAX_SAFE_INTEGER` (or larger, since only `isFinite` + integer-check is enforced, not a max value), `temp_data_length += m.payload.data_length + 4` and the subsequent `Math.ceil(temp_data_length * constants.TEMP_DATA_PRICE)` computation can lose precision or produce values whose relation to the declared fee no longer reflects the real (non-existent) data size — the same "trust an unchecked length before arithmetic" root cause flagged in CVE-2024-53146's `decode_cb_compound4res()`.

### Impact Explanation
This weakens the deterministic fee/commission accounting that all messages rely on for correct DAG bookkeeping (`headers_commission`/`payload_commission` validation gate at `validation.js:257-268`). While the computation is deterministic across nodes (all nodes run the same JS `Number` arithmetic and would therefore agree on the same possibly-wrong result rather than disagreeing), it removes any real bound on the value an author can force into `payload_commission` math via a completely fabricated `data_length` with no backing data. This is a genuine violation of the invariant that byte fees paid by a unit must reflect real content size — a unit can claim/pay for a `temp_data` message whose true size is unverifiable and unenforced once it is old enough to skip the "data present" check, undermining the fee model used for temp-data storage pricing (`getPaidTempDataFee`).

### Likelihood Explanation
Reachable by any unprivileged unit author: crafting a `temp_data` app message without a `data` field but with a large `data_length` requires only choosing `objUnit.timestamp` old enough to exceed `constants.TEMP_DATA_PURGE_TIMEOUT`, which is entirely attacker-controlled input in a self-posted unit. No special privileges, hub/peer compromise, or node bugs are required — only the fields exposed in `validateInlinePayload()`'s `temp_data` case.

### Recommendation
- Enforce an explicit upper bound on `payload.data_length` (e.g., bounded by `constants.MAX_UNIT_LENGTH` or a dedicated `MAX_TEMP_DATA_LENGTH`) in `validation.js`'s `temp_data` case, independent of whether `data` is present.
- Avoid trusting `data_length` unconditionally when `data` is omitted; if this "already purged" trust path is required, only allow it for units whose payload hash / data_length were previously validated against real content (i.e., verified at first-seen time and never mutable afterward), and re-verify bounds at every consumption site (`extractTempData`, `getTempDataLength`).
- In `object_length.js`, guard the `data_length + 4` and `Math.ceil(... * constants.TEMP_DATA_PRICE)` arithmetic with explicit `Number.isSafeInteger()`/range checks before use, rejecting the unit if any temp_data length or resulting fee exceeds safe-integer bounds.

### Proof of Concept
1. Craft a unit with a single `temp_data` message: `{ app: 'temp_data', payload_location: 'inline', payload: { data_length: Number.MAX_SAFE_INTEGER - 1, data_hash: '<44-char base64>' } }` (no `data` field).
2. Set `objUnit.timestamp` to a value older than `constants.TEMP_DATA_PURGE_TIMEOUT` seconds before submission time, and `objValidationState.bAA` false.
3. `validateInlinePayload()`'s `temp_data` branch (`validation.js:1966-2000`) skips the length/hash cross-check (the `"data" in payload` block) and only requires `Math.round(Date.now()/1000) - objUnit.timestamp >= TEMP_DATA_PURGE_TIMEOUT`, so it passes with the attacker-chosen `data_length`.
4. `object_length.getTotalPayloadSize()`/`getTempDataLength()` (`object_length.js:79-112`) then compute `temp_data_length` and the corresponding fee directly from the unchecked huge `data_length`, with no upper-bound validation anywhere in the chain.

**Note on confidence:** I was not able to further verify (within the available tool budget) the exact value of `constants.TEMP_DATA_PURGE_TIMEOUT`, nor whether a separate lower-bound-on-timestamp check elsewhere in unit/parent validation would prevent an author from choosing an arbitrarily old `objUnit.timestamp`. These would need to be confirmed to fully weaponize the PoC end-to-end; if such a timestamp floor exists, the primary residual issue is simply the missing upper bound on `data_length` itself, which is confirmed directly from the code shown above.

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

**File:** validation.js (L1966-2000)
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
```

**File:** validation_utils.js (L20-29)
```javascript
function isInteger(value){
	return typeof value === 'number' && isFinite(value) && Math.floor(value) === value;
};

/**
 * True if int is an integer strictly greater than zero.
 */
function isPositiveInteger(int){
	return (isInteger(int) && int > 0);
}
```

**File:** object_length.js (L79-112)
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
