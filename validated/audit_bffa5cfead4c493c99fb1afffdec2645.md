### Title
Uncaught TypeError (NULL/undefined dereference) when AA formula's `unit[...]` selector references a unit with a non-inline `temp_data` message - ([File: formula/evaluation.js])

### Summary
The `'unit'` case of the AA formula evaluator dereferences `m.payload.data` for every `temp_data` message found in a referenced unit, without checking that `m.payload` actually exists. A `temp_data` message is only guaranteed to carry a `payload` object when its `payload_location` is `"inline"`; when `payload_location` is `"none"` (data already purged, or simply not inlined), `payload` is absent from the unit. Evaluating `unit['<hash>']` in an AA formula against such a unit throws an uncaught `TypeError`, analogous to the NULL pointer dereference described in CVE-2018-13441 where a crafted payload to a listener causes a crash.

### Finding Description
`validateMessages`/`validateInlinePayload` in `validation.js` only require a `payload` field on a message when `payload_location === "inline"`; for any other location (`"none"`, `"uri"`) the field must be absent: [1](#0-0) 

This means a fully valid, already-accepted unit can legally contain a `temp_data` message with `payload_location: "none"` and no `payload` property at all (this is the normal state once the temp data has been purged, or before it is ever inlined) — see the corresponding handling in `validateInlinePayload`'s `"temp_data"` branch, where the `payload` object is only required/validated when `payload_location` is inline: [2](#0-1) 

When an Autonomous Agent's oscript uses the `unit[...]` selector to load an arbitrary unit (a feature reachable simply by pointing at any known unit hash, including ones sent by an unprivileged trigger sender or referenced by the AA author), `formula/evaluation.js` retrieves the joint and then unconditionally iterates its messages, deleting `payload.data` for every `temp_data` message without verifying `payload` exists: [3](#0-2) 

If the referenced unit contains a `temp_data` message whose `payload_location` is not `"inline"` (so `payload` is `undefined`), the line `delete m.payload.data;` throws `TypeError: Cannot read properties of undefined (reading 'data')` (or equivalent “cannot convert undefined or null to object” for `delete`). This exception is not wrapped in a `try/catch` anywhere in this call chain (`evaluate` → `storage.readJoint` → `ifFound` callback), so it propagates out of the asynchronous callback and crashes the Node.js process — the functional equivalent of the qh_help NULL pointer dereference: a single crafted/selected input value causes an unhandled dereference of a non-existent object.

### Impact Explanation
Any AA whose oscript definition uses the `unit[...]` selector to read a unit (a common and documented feature for AAs to inspect arbitrary DAG units) can be forced to crash every full node that evaluates that AA's response, once a trigger references — directly or indirectly via a chosen constant/parameter — a unit containing a non-inline `temp_data` message. Because AA execution must be deterministic and is performed by every node processing/validating the DAG, a crash here is not merely a “this node dies” bug: it stops the affected node from continuing to validate/process new units (crash-restart loop), and if the referenced unit is reachable by all full nodes (it is a public DAG unit), this can be triggered repeatedly by anyone who can afford to fire the trigger, degrading network liveness. This matches the “node disagreement on validity/stability” / “network unable to confirm new units” impact bucket, since crashing nodes cannot continue validating and advancing MC stability.

### Likelihood Explanation
The path requires an AA that dereferences a unit via `unit[...]` (fully within the reach of any AA author, who is an explicitly in-scope actor) and a trigger sender that causes evaluation of that selector against a unit containing a `temp_data` message with non-inline payload location — a state that occurs naturally whenever temp data is purged (this is standard behavior, see `TEMP_DATA_PURGE_TIMEOUT` handling in `validation.js`), or can be deliberately created by posting a `temp_data` message with `payload_location: "none"` from the start. No special privileges, mining power, or witness/oracle status are required — an ordinary user with control over an AA definition and/or a trigger unit can hit this path.

### Recommendation
In `formula/evaluation.js`, guard the `temp_data` cleanup loop to check that `m.payload` exists before deleting `data` from it, e.g.:
```js
for (let m of objUnit.messages)
    if (m.app === "temp_data" && m.payload)
        delete m.payload.data;
```
Additionally, wrap the `ifFound` callback logic (or the whole `storage.readJoint` invocation) in a `try/catch` that reports a formula evaluation error via `setFatalError`/`cb(false)` instead of letting exceptions escape into the async callback and crash the process, consistent with the defensive pattern already used elsewhere in this file (e.g. `setFatalError` calls guarding malformed asset/field access).

### Proof of Concept
1. Post/accept a unit `U1` containing a message `{ app: "temp_data", payload_location: "none", payload_hash: "<valid-hash>", payload_uri_hash: ... }` with no `payload` field — this is valid per current `validation.js` rules (payload is only required when `payload_location === "inline"`), e.g. it naturally occurs after `TEMP_DATA_PURGE_TIMEOUT` elapses for any previously-inlined `temp_data` message.
2. Deploy an AA whose oscript definition contains a formula referencing that unit, e.g.:
   ```
   $u = unit['<U1_hash>'];
   ```
3. Send a trigger unit to the AA so that the formula is evaluated.
4. During evaluation, `formula/evaluation.js`'s `'unit'` case reaches `ifFound`, iterates `objUnit.messages`, finds the `temp_data` message, and executes `delete m.payload.data` where `m.payload` is `undefined`, throwing an uncaught `TypeError` that is not caught anywhere in the call chain, crashing the evaluating node process.

### Citations

**File:** validation.js (L227-234)
```javascript
			if (m.payload_location !== "inline") {
				if ("payload" in m)
					return callbacks.ifJointError("payload must be absent when payload_location is not inline");
				continue;
			};
			if (!("payload" in m) || m.payload === null)
				return callbacks.ifJointError("missing payload");
			
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

**File:** formula/evaluation.js (L1608-1616)
```javascript
							// ignore units that are not stable or created at a later mci
							if (unit_mci === null || unit_mci > mci)
								return cb(false);
							objectHash.cleanNulls(objUnit); // removes actual_tps_fee which is null in AA responses
							for (let m of objUnit.messages)
								if (m.app === "temp_data")
									delete m.payload.data; // delete temp data if it is not purged yet
							cb(new wrappedObject(objUnit));
						}
```
