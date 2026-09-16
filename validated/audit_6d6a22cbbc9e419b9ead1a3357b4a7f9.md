Confirmed: `writer.js` acquires a single global `mutex.lock(["write"])` before writing any unit [1](#0-0) , so ocore has exactly the same single-writer bottleneck as Bugsink: one expensive write transaction (many INSERTs for one unit) delays digestion/writing of every other incoming unit until it commits.

### Title
DoS via unbounded attestation profile fields causing a single oversized write transaction to stall the single-writer node - (File: writer.js, validation.js)

### Summary
An unprivileged unit poster can submit an `attestation` message whose `profile` object contains thousands of key/value fields. Unlike every structurally similar "many small sub-items in one message" construct in ocore (data feeds, poll choices, spend proofs, asset denominations/attestors), the `attestation.profile` object has **no dedicated anti-spam cardinality limit**. It is only bounded by the generic, much looser `isTooDeeplyNestedOrHasTooManyNodes` node-count check (default limit 10000) applied to the whole unit. `writer.js` then iterates every profile field and issues one `INSERT INTO attested_fields` per valid field inside the single global write transaction guarded by the process-wide `mutex.lock(["write"])`, exactly the "single-writer, one expensive transaction blocks all other digestion" pattern described in the Bugsink advisory.

### Finding Description
Validation of the `attestation` message only checks that `payload.profile` is a non-empty object, with no cap on the number of keys: [2](#0-1) 

Compare this to sibling per-message collections that all have explicit anti-spam constants: [3](#0-2) 
- `MAX_DATA_FEEDS_PER_MESSAGE = 1024` enforced at `Object.keys(payload).length * objUnit.authors.length > constants.MAX_DATA_FEEDS_PER_MESSAGE` [4](#0-3) 
- `MAX_CHOICES_PER_POLL`, `MAX_SPEND_PROOFS_PER_MESSAGE`, `MAX_DENOMINATIONS_PER_ASSET_DEFINITION`, `MAX_ATTESTORS_PER_ASSET` are similarly enforced elsewhere.

The only global guard that indirectly caps the number of `profile` keys is the unit-wide node-count check, applied once per unit early in `validate()`: [5](#0-4) [6](#0-5) 
This limit (10000 nodes) is 10–80× looser than the dedicated per-message caps used elsewhere (128/1024), and it is shared across the whole unit rather than scoped to a single message, so a single `attestation` message can still legitimately contain several thousand `field: value` pairs (each within `MAX_PROFILE_FIELD_LENGTH`/`MAX_PROFILE_VALUE_LENGTH`) and still pass validation.

When the unit is written, `writer.js` loops over every field of `attestation.profile` and issues a separate `INSERT INTO attested_fields` query for each one that satisfies the length checks, in addition to the `INSERT INTO attestations` row — all inside the same write transaction: [7](#0-6) 

This write happens under a single, process-wide write mutex/transaction: [8](#0-7) 

Because ocore (like Bugsink) uses a single-writer architecture, one unit with a maximally-stuffed `profile` object turns into thousands of sequential INSERTs executed inside one held write lock/transaction, delaying the writing/digestion of every other unit that is queued behind it — the same "expensive write transaction blocks all other digestion" DoS class described in the advisory.

### Impact Explanation
While each write itself doesn't corrupt data or leak information, holding the single global write mutex for the duration of thousands of row insertions causes ingestion of other legitimately posted units (payments, AA triggers, etc.) to stall for the duration of that transaction, temporarily degrading availability of the whole node. This matches the “temporary denial of service for other events” impact class from the reference advisory (CWE-400 / availability-only impact), scoped to unit posting rather than a network peer.

### Likelihood Explanation
Likelihood is Medium: any address with authentifiers can attach an `attestation` message to a normal unit; it costs the normal headers/payload commission for the extra bytes, so it is not free, but the cost is not specifically calibrated against the per-row DB write cost the way sibling collections were explicitly capped. An attacker only needs to build a moderately sized profile object (thousands of short key/value pairs, each individually small) to reach the unit-wide 10000-node ceiling and trigger thousands of `attested_fields` inserts in a single held write transaction.

### Recommendation
Add a dedicated anti-spam constant (e.g., `MAX_PROFILE_FIELDS_PER_ATTESTATION`) analogous to `MAX_DATA_FEEDS_PER_MESSAGE`/`MAX_CHOICES_PER_POLL`, and enforce `Object.keys(payload.profile).length <= MAX_PROFILE_FIELDS_PER_ATTESTATION` in the `"attestation"` case of `validateInlinePayload` in `validation.js` (mirroring the pattern at lines 1925–1932), so the number of `attested_fields` rows written per unit is tightly bounded independent of the generic whole-unit node-count check.

### Proof of Concept
1. Craft a unit with a single `attestation` message: `{ address: <valid address>, profile: { f0: "v0", f1: "v1", ..., f4999: "v4999" } }`, where each `field`/`value` pair stays within `MAX_PROFILE_FIELD_LENGTH` (50) / `MAX_PROFILE_VALUE_LENGTH` (100) and the whole unit stays under the ~10000-node limit and `MAX_UNIT_LENGTH`.
2. Sign and post the unit as a normal single-authored transaction (passes `validateInlinePayload`'s `attestation` check, which never inspects field count).
3. When the unit is accepted, `writer.js` acquires the global write lock and executes ~5000 sequential `INSERT INTO attested_fields` statements in one transaction, holding the lock for the whole duration.
4. Repeat/pipeline such units to keep the single writer continuously occupied, delaying digestion of concurrently submitted, unrelated units.

### Citations

**File:** writer.js (L24-53)
```javascript
async function saveJoint(objJoint, objValidationState, preCommitCallback, onDone) {
	var objUnit = objJoint.unit;
	console.log("\nsaving unit "+objUnit.unit);
	var arrQueries = [];
	var commit_fn;
	if (objValidationState.conn && !objValidationState.batch)
		throw Error("conn but not batch");
	var bInLargerTx = (objValidationState.conn && objValidationState.batch);
	const bCommonOpList = objValidationState.last_ball_mci >= constants.v4UpgradeMci;

	const unlock = objValidationState.bUnderWriteLock ? () => { } : await mutex.lock(["write"]);
	console.log("got lock to write " + objUnit.unit);

	function initConnection(handleConnection) {
		if (bInLargerTx) {
			profiler.start();
			commit_fn = function (sql, cb) { cb(); };
			return handleConnection(objValidationState.conn);
		}
		db.takeConnectionFromPool(function (conn) {
			profiler.start();
			conn.addQuery(arrQueries, "BEGIN");
			commit_fn = function (sql, cb) {
				conn.query(sql, function () {
					cb();
				});
			};
			handleConnection(conn);
		});
	}
```

**File:** writer.js (L205-216)
```javascript
						case "attestation":
							var attestation = message.payload;
							conn.addQuery(arrQueries, "INSERT INTO attestations (unit, message_index, attestor_address, address) VALUES(?,?,?,?)", 
								[objUnit.unit, i, objUnit.authors[0].address, attestation.address]);
							for (var field in attestation.profile){
								var value = attestation.profile[field];
								if (field == field.trim() && field.length <= constants.MAX_PROFILE_FIELD_LENGTH
										&& typeof value === 'string' && value == value.trim() && value.length <= constants.MAX_PROFILE_VALUE_LENGTH)
									conn.addQuery(arrQueries, 
										"INSERT INTO attested_fields (unit, message_index, attestor_address, address, field, value) VALUES(?,?, ?,?, ?,?)",
										[objUnit.unit, i, objUnit.authors[0].address, attestation.address, field, value]);
							}
```

**File:** validation.js (L154-155)
```javascript
	if (isTooDeeplyNestedOrHasTooManyNodes(objUnit))
		return bAA ? callbacks.ifUnitError("unit is too deeply nested") : callbacks.ifJointError("unit is too deeply nested");
```

**File:** validation.js (L1925-1932)
```javascript
		case "data_feed":
			if (objValidationState.bHasDataFeed)
				return callback("can be only one data feed");
			objValidationState.bHasDataFeed = true;
			if (!isNonemptyObject(payload))
				return callback("data feed payload must be non-empty object");
			if (Object.keys(payload).length * objUnit.authors.length > constants.MAX_DATA_FEEDS_PER_MESSAGE)
				return callback("too many data feeds in message");
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

**File:** constants.js (L42-56)
```javascript
// anti-spam limits
exports.MAX_AUTHORS_PER_UNIT = 16;
exports.MAX_PARENTS_PER_UNIT = 16;
exports.MAX_MESSAGES_PER_UNIT = 128;
exports.MAX_SPEND_PROOFS_PER_MESSAGE = 128;
exports.MAX_INPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_OUTPUTS_PER_PAYMENT_MESSAGE = 128;
exports.MAX_CHOICES_PER_POLL = 128;
exports.MAX_CHOICE_LENGTH = 64;
exports.MAX_DENOMINATIONS_PER_ASSET_DEFINITION = 64;
exports.MAX_ATTESTORS_PER_ASSET = 64;
exports.MAX_DATA_FEED_NAME_LENGTH = 64;
exports.MAX_DATA_FEED_VALUE_LENGTH = 64;
exports.MAX_DATA_FEEDS_PER_MESSAGE = 1024;
exports.MAX_AUTHENTIFIER_LENGTH = 4096;
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
