### Title
Uncaught TypeError (NULL/undefined dereference) in oscript `unit()` getter when referenced unit has a non-inline `temp_data` message - (File: formula/evaluation.js)

### Summary
The oscript `unit` operator, reachable from any AA definition or trigger, reads an arbitrary already-confirmed unit from storage and then unconditionally accesses `m.payload.data` for every message with `app === "temp_data"`, without first verifying that `m.payload` actually exists. This mirrors the CVE-2017-6847 pattern of dereferencing a lazily/deferred-loaded structure member without validating the structure's shape first, resulting in a NULL/undefined pointer dereference.

### Finding Description
In the `'unit'` case of the oscript evaluator, after a unit is read from storage and passes the mci/sequence checks, the code iterates the unit's messages and deletes any temp-data payload: [1](#0-0) 

`objUnit.messages` for a stored unit can contain a message with `app === "temp_data"` whose `payload_location` is not `"inline"`. Per the payload-hash validation logic, non-inline messages are expected to have **no** `payload` field at all: [2](#0-1) 

Nothing in the `'unit'` evaluator branch checks `m.payload_location` or `("payload" in m)` before dereferencing `m.payload.data`. If such a message reaches this code, `m.payload` is `undefined`, and `delete m.payload.data` throws `TypeError: Cannot convert undefined or null to object`. This throw happens synchronously inside the `storage.readJoint` `ifFound` callback: [3](#0-2) 

Because this callback runs outside of any try/catch in the AA formula evaluator's async flow, an uncaught exception here propagates out of the database/event-loop callback stack.

### Impact Explanation
Any unprivileged AA author can write an oscript definition/trigger response that calls `unit(<some_confirmed_unit_hash>)` where the referenced unit contains a `temp_data` message using a non-inline `payload_location`. When any node (including witnesses and other validating full nodes) evaluates this AA in response to a posted trigger, the uncaught `TypeError` crashes the Node.js process handling AA evaluation, which occurs during unit/trigger validation. This is a denial-of-service condition: nodes processing the poisoned AA trigger unit repeatedly crash, preventing them from validating/confirming new units — matching the "network unable to confirm new units" impact class.

### Likelihood Explanation
The trigger is entirely attacker-controlled: an attacker only needs to (1) post any ordinary unit containing a non-inline `temp_data` message that gets confirmed, and (2) define/trigger an AA whose oscript calls `unit()` referencing that unit's hash. Both actions are available to any unprivileged unit poster / AA author, requiring no special permissions, hub cooperation, or malicious peer/node behavior.

### Recommendation
In the `'unit'` case of `formula/evaluation.js`, guard the temp-data cleanup with an existence check before dereferencing, e.g.:
```js
for (let m of objUnit.messages)
    if (m.app === "temp_data" && m.payload_location === "inline" && m.payload)
        delete m.payload.data;
```
Additionally, wrap the `ifFound` callback body in a try/catch that calls `setFatalError`/`cb(false)` instead of letting exceptions escape, consistent with how other unexpected-shape errors are handled elsewhere in the evaluator.

### Proof of Concept
1. Post/confirm a normal unit `U` containing a message `{app: "temp_data", payload_location: "hash", payload_hash: "<hash>"}` (no `payload` field, consistent with `hasValidPayloadHashes` for non-inline messages).
2. Define/trigger an AA whose oscript includes `unit("U")` (or any expression that resolves to `U`'s hash) in a `bounce`/`response`/`if` clause.
3. When the AA is triggered, evaluation reaches the `'unit'` branch, `storage.readJoint` resolves with `objJoint.unit.messages` containing the `temp_data` message without a `payload` field, and `delete m.payload.data` throws `TypeError`, crashing the evaluating node.

### Citations

**File:** formula/evaluation.js (L1592-1617)
```javascript
					// 3. check the units from the db
					console.log('---- reading', unit);
					storage.readJoint(conn, unit, {
						ifNotFound: function () {
							cb(false);
						},
						ifFound: function (objJoint, sequence) {
							console.log('---- found', unit);
							if (sequence !== 'good') // bad units don't exist for us
								return cb(false);
							var objUnit = objJoint.unit;
							if (bPostPemCurvesFix)
								delete objUnit.actual_tps_fee; // might be null in stable units stabilized in the same batch
							if (objUnit.version === constants.versionWithoutTimestamp)
								objUnit.timestamp = 0;
							var unit_mci = objUnit.main_chain_index;
							// ignore units that are not stable or created at a later mci
							if (unit_mci === null || unit_mci > mci)
								return cb(false);
							objectHash.cleanNulls(objUnit); // removes actual_tps_fee which is null in AA responses
							for (let m of objUnit.messages)
								if (m.app === "temp_data")
									delete m.payload.data; // delete temp data if it is not purged yet
							cb(new wrappedObject(objUnit));
						}
					});
```

**File:** validation.js (L55-67)
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
```
