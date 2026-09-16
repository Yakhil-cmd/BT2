### Title
Missing profile field/value length validation in unit validation - (File: validation.js)

### Summary
`validation.js`'s handling of the `profile` app message does not enforce the length limits that the rest of the codebase defines and relies on (`MAX_PROFILE_FIELD_LENGTH`, `MAX_PROFILE_VALUE_LENGTH`), unlike every other size-sensitive message type (`data_feed`, `poll`, `vote`, `asset_attestors`, etc.) which explicitly bound field/value/choice lengths during validation.

### Finding Description
`constants.js` defines `MAX_PROFILE_FIELD_LENGTH = 50` and `MAX_PROFILE_VALUE_LENGTH = 100` [1](#0-0) , and these constants are referenced in `writer.js` (persistence layer) [2](#0-1) , implying that profile field names and values are expected to be bounded when they are written/consumed downstream.

However, in `validation.js`, the `profile` case falls straight through into the generic `data` case, which only checks that the payload is a non-null object — it performs no per-field-name or per-value length check at all: [3](#0-2) 

Contrast this with other message types in the same function that do enforce equivalent per-field limits at validation time, e.g. `data_feed` (`MAX_DATA_FEED_NAME_LENGTH`/`MAX_DATA_FEED_VALUE_LENGTH`) [4](#0-3)  and `poll` choices (`MAX_CHOICE_LENGTH`) [5](#0-4) . The only global backstop for a `profile` message is the overall unit-size ceiling `MAX_UNIT_LENGTH` (5 MB) checked via `objectLength.getTotalPayloadSize` [6](#0-5) , so an attacker-controlled `profile` message can carry field names/values orders of magnitude larger than the `50`/`100`-character limits assumed elsewhere in the codebase, as long as the whole unit stays under 5 MB.

### Impact Explanation
Because `validation.js` accepts oversized profile field names/values that violate the invariants `writer.js` was written against (`MAX_PROFILE_FIELD_LENGTH`/`MAX_PROFILE_VALUE_LENGTH`), any code path in `writer.js` (or downstream consumers) that assumes these bounds hold when persisting/processing a validated unit could behave inconsistently — e.g., truncation-based data loss, or differing behavior between storage backends (SQLite vs MySQL/RocksDB) if one enforces column-width constraints strictly and errors while another silently truncates. This is exactly the mismatch-between-validation-and-persistence pattern described in the HAL-27 report (insufficient size validation of user-controlled fields leading to resource/consistency issues). I was not able to fully confirm from the available index whether the mismatch causes a hard write failure (potential node crash / unit rejection inconsistency between full nodes) or silent truncation, since I could not retrieve the exact `writer.js` profile-insertion code — this should be verified directly against the full file before treating the impact as confirmed Medium/High.

### Likelihood Explanation
Any unprivileged unit poster can attach a `profile` message to a unit with oversized field names/values and pass current validation, since the size ceiling is only the generic 5 MB `MAX_UNIT_LENGTH` bound rather than the intended `50`/`100`-character per-field bound. This makes the malformed input trivially reachable through the normal unit-posting path.

### Recommendation
Add explicit length checks for the `profile` app in `validateInlinePayload` (validation.js), mirroring the treatment of `data_feed`/`poll`: for each `field` and `value` in the profile payload, reject the message if `field.length > constants.MAX_PROFILE_FIELD_LENGTH` or `value.length > constants.MAX_PROFILE_VALUE_LENGTH`, so that units the network would treat as invalid are rejected uniformly by all nodes rather than relying on writer-side handling.

### Proof of Concept
1. Compose a unit with a `profile` message whose payload is `{ "<field of length > 50>": "<value of length > 100>" }`.
2. Submit it through the normal validate flow; `validateInlinePayload`'s `profile`/`data` case only checks `typeof payload === "object"` [7](#0-6) , so the unit passes validation as long as total unit size < `MAX_UNIT_LENGTH`.
3. Observe how `writer.js`'s profile-persistence logic (which references `MAX_PROFILE_FIELD_LENGTH`/`MAX_PROFILE_VALUE_LENGTH`) handles the oversized field/value — this step requires manual verification against the full `writer.js` source, which could not be completely retrieved in this analysis.

### Citations

**File:** constants.js (L61-62)
```javascript
exports.MAX_PROFILE_FIELD_LENGTH = 50;
exports.MAX_PROFILE_VALUE_LENGTH = 100;
```

**File:** writer.js (L1-1)
```javascript
/*jslint node: true */
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

**File:** validation.js (L1796-1811)
```javascript
			if (!isNonemptyArray(payload.choices))
				return callback("no choices in poll");
			if (payload.choices.length > constants.MAX_CHOICES_PER_POLL)
				return callback("too many choices in poll");
			let seenChoices = Object.create(null);
			for (var i=0; i<payload.choices.length; i++) {
				if (typeof payload.choices[i] !== 'string')
					return callback("all choices must be strings");
				if (payload.choices[i].trim().length === 0)
					return callback("all choices must be longer than 0 chars");
				if (payload.choices[i].length > constants.MAX_CHOICE_LENGTH)
					return callback("all choices must be "+ constants.MAX_CHOICE_LENGTH + " chars or less");
				if (seenChoices[payload.choices[i]])
					return callback("all choices must be different");
				seenChoices[payload.choices[i]] = true;
			}
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
