### Title
Type confusion in "data"/"profile" message payload validation allows array to bypass object-only check - (File: validation.js)

### Summary
`validateInlinePayload()` in `validation.js` validates the payload of `data` and `profile` app messages using only `typeof payload !== "object" || payload === null`, which is true for both plain objects and arrays in JavaScript. Unlike the neighboring `temp_data` case in the same switch statement, which explicitly adds `Array.isArray(payload)` rejection, the `data`/`profile` branch has no such check, allowing a unit author to post an array as the payload of a `data` or `profile` message.

### Finding Description
In `validation.js`, the switch on `objMessage.app` handles several message types payload-checked by `typeof`: [1](#0-0) 

The `data`/`profile` case:
```
case "data":
    if (typeof payload !== "object" || payload === null)
        return callback(objMessage.app+" payload must be object");
    return callback();
```
does not exclude arrays, because `typeof []` is `"object"` in JavaScript. Immediately below, the `temp_data` case for the same general category of message explicitly guards against this exact ambiguity:
```
if (typeof payload !== "object" || payload === null)
    return callback("temp_data payload must be an object");
if (Array.isArray(payload))
    return callback("temp_data payload must not be an array");
```
This shows the codebase authors are aware that `typeof x === "object"` includes arrays and elsewhere deliberately reject them, but forgot to do so for `data`/`profile`. This is the same root-cause class as CVE-2016-7979 (a validator/parser assuming a value is of one concrete type based on an insufficient type check, allowing an unexpected type to slip through and be treated as the assumed type downstream).

For AA-authored/AA-nested `data` messages, `aa_validation.js` is stricter and calls `isNonemptyObject(payload)`, which does reject arrays via `!Array.isArray(obj)`: [2](#0-1) 
so the confusion is confined to the general unit-validation path (`validation.js`), reachable by any ordinary unit author posting a `data` or `profile` message, not an AA definition.

### Impact Explanation
An attacker can post a unit with a `data` message whose payload is a JSON array (e.g. `[1,2,3]`) instead of an object, and it will pass validation as a legitimate `data` message. Because such a unit becomes part of the stable DAG, this "malformed but validated" payload propagates to every consumer of `data` messages, including:
- AA triggers: when an ordinary unit sends a `data` message to an AA address, `trigger.data` is populated from `objUnit.messages` payload and wrapped for oscript evaluation as a `wrappedObject`. Oscript logic written by AA authors that assumes `trigger.data` is a JSON object (e.g. uses `is_assoc`, `keys`, or direct named-field access assuming an object) can behave unexpectedly when handed an array, since the shape differs from what the AA schema/documentation promises for `data` messages. This can lead to logic bypass in the AA (e.g. conditions that are supposed to gate fund transfers behave differently when `trigger.data` is an array rather than an object), risking incorrect fund release/loss in AAs that don't defensively check `is_assoc(trigger.data)` before use.
- Any wallet/UI or downstream tooling that assumes `data` message payload is a JSON object per the protocol's documented format may mis-parse or crash when processing an array, which is a functional/logic bypass of an intended invariant rather than a hardening-only issue.

The severity is bounded by the fact this doesn't directly enable double-spend or supply inflation by itself, but it does allow bypassing an intended data-shape invariant enforced by full-node consensus validation, and downstream AA/wallet code that relies on that invariant can then reach unsafe states (unauthorized behavior, fund mishandling) if it doesn't perform its own type check — mirroring how the Ghostscript bug allowed a type-confused object to bypass the intended safety gate and be misused downstream.

### Likelihood Explanation
Trivial to trigger: any unprivileged unit author can compose and post a unit containing a `data` (or `profile`) message with an array payload using standard unit-composition APIs; no special privileges, AA definition rights, or specific network conditions are required. The check is deterministic and always taken for this app type.

### Recommendation
Add an explicit `Array.isArray(payload)` rejection to the `data`/`profile` case in `validateInlinePayload()` in `validation.js`, matching the pattern already used for `temp_data`:
```
case "data":
    if (typeof payload !== "object" || payload === null || Array.isArray(payload))
        return callback(objMessage.app+" payload must be object");
    return callback();
```
Also audit all downstream consumers (AA trigger data handling in `aa_composer.js`/`formula/evaluation.js`, wallet message display code) to defensively verify the shape of `data` payloads rather than assuming they are non-array objects, in case previously-stable units with array payloads already exist on the DAG.

### Proof of Concept
1. Compose a unit with a message `{ app: "data", payload: [1, 2, 3] }` (an array), sign and post it through the normal unit-composition/posting flow used by any wallet or `composer.js` API.
2. Observe that `validateInlinePayload()` in `validation.js` (case `"data"`) accepts it because `typeof [1,2,3] === "object"` and it is not `null`.
3. Send this unit as a trigger to an AA whose oscript formula does `trigger.data.someField` or similar without first checking `is_assoc(trigger.data)`; observe the AA's evaluation processes `trigger.data` as an array (e.g. `trigger.data.someField` resolves via array/object property lookup) rather than being rejected up front as malformed, contrary to what AA authors are led to expect from the documented `data` message schema. [3](#0-2)

### Citations

**File:** validation.js (L1954-1972)
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

		case "temp_data":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci)
				return callback("cannot use temp_data yet");
			if (typeof payload !== "object" || payload === null)
				return callback("temp_data payload must be an object");
			if (Array.isArray(payload))
				return callback("temp_data payload must not be an array");
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
