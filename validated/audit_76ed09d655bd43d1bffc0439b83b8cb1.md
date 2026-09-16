### Title
Fixed-size accounting for `parent_units` undercounts headers commission for units with more than 2 parents - (File: object_length.js)

### Summary
`object_length.js` computes `headers_commission` for a unit by deleting the real `parent_units` array from the cloned header object and adding back a **fixed** constant `PARENT_UNITS_SIZE = 2*44` (i.e. exactly two 44‑byte hashes), instead of accounting for the actual number of parent hashes present in the unit (which the protocol allows to be up to `MAX_PARENTS_PER_UNIT = 16`, per `constants.js`). This is directly analogous to the Linux kernel CVE-2021-47274 root cause: a length/size check that fails to account for an additional variable-size component (`sizeof(entry->array[0])`), so the computed length silently diverges from the real serialized size of the data structure. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`getHeadersSize()` strips `objUnit.parent_units` from the cloned header and replaces its contribution with the hard-coded constant `PARENT_UNITS_SIZE` (88 bytes, i.e. two 44-character hashes) plus, when applicable, the key-name length `"parent_units".length`: [4](#0-3) 

However, `parent_units` is an array whose length is bounded only by `constants.MAX_PARENTS_PER_UNIT = 16`, not fixed at 2. Every additional parent hash beyond two (up to 14 more 44-character base64 strings, i.e. up to 616 extra bytes) is completely omitted from the size computation used to derive `headers_commission`.

`validation.js` then only checks that the *declared* `headers_commission` equals the value returned by this (structurally flawed) function — it never independently re-derives the true byte size of the serialized `parent_units` array: [5](#0-4) 

Because the check is self-referential (declared commission must equal the buggy computed commission, not the real size), an attacker who posts a unit with many parents (up to 16) pays exactly the same `headers_commission` as a unit with 2 parents, since the extra parent hash bytes are never reflected in the size formula. This mirrors the kernel bug pattern precisely: the length check omits a component (`array[0]`/parent hash entries) that should scale with the actual data, so the "checked" length is not the real length, and downstream logic (commission accounting / anti-spam and `MAX_UNIT_LENGTH` enforcement) operates on an incorrect value.

### Impact Explanation
`headers_commission` is a core economic accounting value in the DAG: it determines how much of the unit's paid commission is earned by other units that reference it (headers commission recipients), and `headers_commission + payload_commission` is also checked against `constants.MAX_UNIT_LENGTH` to reject oversized units: [6](#0-5) 

By posting a unit with up to `MAX_PARENTS_PER_UNIT` (16) parents instead of 2, an attacker can inflate the real serialized/storage/graph-traversal cost of the unit onto the DAG while the protocol charges/attributes commission as if only 2 parents were present. This is a reachable, single-posted-unit anti-spam/economic-accounting bypass: it lets an attacker under-pay for DAG storage and graph complexity they impose on the network (more parents to walk, more `parent_units` bytes to store/hash/transmit), and skews the `headers_commission` distributed to referencing peers, degrading the correctness of the fee/commission mechanism across the network. It does not cause classic memory corruption (JS has bounds-checked buffers), but the "wrong length feeding downstream logic that assumes it is correct" root cause and its effect on unit economics and size-limit enforcement satisfy the accepted impact categories of node disagreement/economic distortion in the anti-spam mechanism.

### Likelihood Explanation
Any unpaired unit poster can trivially construct a unit referencing more than 2 valid parent tips (up to 16, which is explicitly allowed by `MAX_PARENTS_PER_UNIT`). No special privileges, network position, or race conditions are required — this is reachable purely through normal unit composition and posting, exercised on every validating node via `validate()` → `getHeadersSize()`.

### Recommendation
Modify `getHeadersSize()` in `object_length.js` to compute the actual size contributed by `parent_units` based on the real array (e.g. `objUnit.parent_units.length * 44` plus separators/keys as applicable, consistent with how `messages` and other fields are measured via `getLength`), instead of the fixed `PARENT_UNITS_SIZE = 2*44` constant. Ensure `headers_commission` validation reflects the true number of parents actually present, and add a regression test asserting that units with 3+ parents produce a proportionally larger required `headers_commission` than 2-parent units.

### Proof of Concept
1. Construct a valid unit with 16 valid parent units (permitted by `MAX_PARENTS_PER_UNIT = 16`) instead of 2.
2. Call `objectLength.getHeadersSize(objUnit)` — observe that the returned value is identical to the size that would be computed for a unit with only 2 parents (delta of the extra 14 × 44-byte hashes is not reflected).
3. Set `objUnit.headers_commission` to this (undercounted) value and submit the unit; `validation.js`'s check `objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission` passes despite the unit actually containing far more parent-hash data than accounted for, demonstrating the commission/size undercounting. [2](#0-1) [5](#0-4)

### Citations

**File:** object_length.js (L6-7)
```javascript
var PARENT_UNITS_SIZE = 2*44;
var PARENT_UNITS_KEY_SIZE = "parent_units".length;
```

**File:** object_length.js (L52-69)
```javascript
function getHeadersSize(objUnit) {
	if (objUnit.content_hash)
		throw Error("trying to get headers size of stripped unit");
	var objHeader = _.cloneDeep(objUnit);
	delete objHeader.unit;
	delete objHeader.headers_commission;
	delete objHeader.payload_commission;
	delete objHeader.oversize_fee;
//	delete objHeader.tps_fee;
	delete objHeader.actual_tps_fee;
	delete objHeader.main_chain_index;
	if (objUnit.version === constants.versionWithoutTimestamp)
		delete objHeader.timestamp;
	delete objHeader.messages;
	delete objHeader.parent_units; // replaced with PARENT_UNITS_SIZE
	var bWithKeys = (objUnit.version !== constants.versionWithoutTimestamp && objUnit.version !== constants.versionWithoutKeySizes);
	return getLength(objHeader, bWithKeys) + PARENT_UNITS_SIZE + (bWithKeys ? PARENT_UNITS_KEY_SIZE : 0);
}
```

**File:** constants.js (L43-44)
```javascript
exports.MAX_AUTHORS_PER_UNIT = 16;
exports.MAX_PARENTS_PER_UNIT = 16;
```

**File:** validation.js (L257-258)
```javascript
		if (objectLength.getHeadersSize(objUnit) !== objUnit.headers_commission)
			return callbacks.ifJointError("wrong headers commission, expected "+objectLength.getHeadersSize(objUnit));
```

**File:** validation.js (L267-268)
```javascript
		if (objUnit.headers_commission + objUnit.payload_commission > constants.MAX_UNIT_LENGTH && !bGenesis && !bAA)
			return callbacks.ifUnitError("unit too large");
```
