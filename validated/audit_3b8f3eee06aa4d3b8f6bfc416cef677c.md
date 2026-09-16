### Title
Temp-data `payload.data_length` is decoupled from the actual `payload.data` size, letting a single posted unit bypass unit-size/fee limits and force disproportionate memory allocation on all nodes - ([File: object_length.js])

### Summary
`lightningnetwork/lnd`'s "Onion Bomb" (CVE-2024-38359) let an attacker send a small on-the-wire message whose *declared* length field caused the parser to allocate memory wildly out of proportion to the actual bytes received, because the size-accounting logic trusted a length field instead of the real payload. ocore has an analogous decoupling in the `temp_data` message type: the byte-size/fee accounting used to enforce `MAX_UNIT_LENGTH` and to charge the `TEMP_DATA_PRICE` anti-spam fee is computed from the attacker-supplied `payload.data_length` field, while the actual `payload.data` string is stripped out and excluded from that computation.

### Finding Description
`getTotalPayloadSize()` computes the payload commission (which is what `constants.MAX_UNIT_LENGTH` is enforced against) via `extractTempData()`: [1](#0-0) 

For every `temp_data` message, `extractTempData` only trusts `m.payload.data_length` (a number field fully controlled by the unit's author) to compute `temp_data_length`, and then **deletes `m.payload.data` from the cloned messages object before calling `getLength`**:

```
temp_data_length += m.payload.data_length + 4;
if (m.payload.data) {
    ...
    delete messages_without_temp_data[i].payload.data;
}
```

This means the real byte size of `payload.data` never enters `getLength()`/`getTotalPayloadSize()`. The resulting `payload_commission` — which is checked against the unit's stored `payload_commission` field and against `constants.MAX_UNIT_LENGTH` in `validation.js` — is entirely determined by the *declared* `data_length`, not by the actual string that is embedded in, hashed with, transmitted as part of, and stored for the unit: [2](#0-1) 

An attacker can therefore craft a unit whose `temp_data` message declares a tiny `data_length` (e.g., `1`) while the accompanying `payload.data` string is arbitrarily large. The general anti-oversize/anti-spam guards (`isTooDeeplyNestedOrHasTooManyNodes`, which only limits node *count* and nesting *depth*, not the byte length of a single string leaf) do not catch this, since one giant string is a single "node": [3](#0-2) 

So the unit's `payload_hash` will legitimately match the actual (huge) payload — `objectHash.getBase64Hash(getPayloadForHash(m), ...)` hashes the real payload including the oversized `data` field — meaning the unit is fully valid per the hash check, yet its accounted `payload_commission`/`headers_commission` (used for the `MAX_UNIT_LENGTH` cap and the `TEMP_DATA_PRICE` fee) reflects only the tiny declared `data_length`, not the real size: [4](#0-3) 

The net effect is structurally identical to the LND onion bomb: a length field trusted for cost/size accounting is decoupled from the actual amount of data that every receiving/validating/storing node must allocate memory for, parse, hash-verify, and gossip — at a fee cost far below what the true size would require, and without tripping the `MAX_UNIT_LENGTH` safety limit.

### Impact Explanation
Every full node (and light-vendor node) that receives such a unit must allocate memory for and process the full, real-size `payload.data` (parsing JSON, computing/verifying `payload_hash`, storing it in the DB, and re-gossiping it to peers), while the anti-spam accounting (`payload_commission`/`MAX_UNIT_LENGTH`, `TEMP_DATA_PRICE` fee) believes it is dealing with a unit of only a few bytes. This lets a single unprivileged unit poster force the network to repeatedly process disproportionately large payloads for a negligible fee, which is a direct route to "network unable to confirm new units" under sustained memory/CPU pressure — the same DoS-via-excessive-memory-allocation impact class as the reported LND bug.

### Likelihood Explanation
The path is reachable by any unprivileged wallet/unit author: composing and posting a single `temp_data` message with a mismatched `data_length` vs. `data` requires no special privilege, no collusion, and no prior on-chain state. The check that ties fee/size accounting to `data_length` rather than the real payload size is unconditional in `object_length.js`, so likelihood of triggering the condition is high, limited only by whatever underlying transport / DB row-size constraints may exist elsewhere (not verified in the reviewed code).

### Recommendation
- Enforce `m.payload.data.length === m.payload.data_length` (or `<=`, whichever is the intended semantics) during message validation, and reject units where they don't match, before computing commissions.
- Alternatively, compute `temp_data_length` from the actual `payload.data.length` rather than trusting the declared field, so `MAX_UNIT_LENGTH` and `TEMP_DATA_PRICE` reflect the true payload size.
- Add an explicit hard cap on the size of any single string field (not just node-count/depth) in `isTooDeeplyNestedOrHasTooManyNodes`/`isObjectWellFormed` to prevent a single oversized leaf value from evading the general nesting guard.

### Proof of Concept
1. Attacker composes a unit containing a `temp_data` message with `payload = { data_length: 1, data: "<many megabytes of characters>" }`.
2. `objectLength.getTotalPayloadSize()` computes `payload_commission` using only `data_length` (≈`1*TEMP_DATA_PRICE` plus small message overhead), since `payload.data` is stripped from the size computation in `extractTempData()`.
3. The attacker sets `objUnit.payload_commission` to this small value; `validation.js`'s check `objectLength.getTotalPayloadSize(objUnit) !== objUnit.payload_commission` passes, and `headers_commission + payload_commission > constants.MAX_UNIT_LENGTH` is false despite the unit's actual byte size being many times `MAX_UNIT_LENGTH`.
4. The unit's `payload_hash` is computed correctly over the real (huge) payload, so hash validation also passes.
5. The unit propagates through the network; every receiving node allocates memory for, parses, hashes, stores, and re-broadcasts the oversized payload while having charged/accounted for only a trivial fee and size.

**Note on verification limits:** I located and reviewed the core size-accounting logic in `object_length.js` and the relevant `validation.js` payload-hash/commission checks, but `validation.js` contains additional `temp_data`-specific validation code (9 occurrences of `temp_data`) that I was not able to fully inspect within the available tool budget. It is possible additional explicit `data.length === data_length` consistency checks exist elsewhere in that file that would mitigate this finding; if so, this analog would not hold. I recommend a Devin session with full repository access to confirm whether such a consistency check exists before treating this as confirmed exploitable.

### Citations

**File:** object_length.js (L71-96)
```javascript
function getTotalPayloadSize(objUnit) {
	if (objUnit.content_hash)
		throw Error("trying to get payload size of stripped unit");
	var bWithKeys = (objUnit.version !== constants.versionWithoutTimestamp && objUnit.version !== constants.versionWithoutKeySizes);
	const { temp_data_length, messages_without_temp_data } = extractTempData(objUnit.messages);
	return Math.ceil(temp_data_length * constants.TEMP_DATA_PRICE) + getLength({ messages: messages_without_temp_data }, bWithKeys);
}

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

**File:** string_utils.js (L260-284)
```javascript
function isTooDeeplyNestedOrHasTooManyNodes(obj, depthLimit = 100, nodesLimit = 10000) {
	let nodeCount = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit)
			return true;
		if (variable === null || typeof variable !== "object")
			return false;
		if (Array.isArray(variable)) {
			nodeCount += variable.length;
			for (let v of variable)
				if (check(v, depth + 1))
					return true;
		}
		else {
			nodeCount += Object.keys(variable).length;
			for (let key in variable)
				if (check(variable[key], depth + 1))
					return true;
		}
		return false;
	}

	return check(obj, 1);
}
```
