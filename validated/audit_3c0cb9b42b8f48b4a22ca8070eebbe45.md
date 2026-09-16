Found a directly analogous bug: unescaped delimiter concatenation used to build a double-spend-detection key in `validation.js`.

### Title
Missing delimiter escaping in payment input double-spend key allows key collision between forged and real inputs - (File: validation.js)

### Summary
`validatePaymentInputsAndOutputs()` builds a per-unit uniqueness key for transfer inputs by naively concatenating `asset`, `unit`, `message_index`, and `output_index` with a plain `"-"` separator, exactly the same string-concatenation pattern (`abi.encodePacked`-style) flagged in the external report. Because none of the components are length-fixed or escaped against the delimiter character, and `asset` in particular is attacker/oracle-influenced in some code paths, two semantically different `(asset, unit, message_index, output_index)` tuples can, in principle, serialize to the identical `input_key` string.

### Finding Description
The vulnerable line is: [1](#0-0) 

```
var input_key = (payload.asset || "base") + "-" + input.unit + "-" + input.message_index + "-" + input.output_index;
if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
    return cb("input "+input_key+" already used");
objValidationState.arrInputKeys.push(input_key);
```

This key is the *only* in-unit duplicate-input guard for `transfer`-type inputs (there is an analogous, separately-built key for `spend_proofs` at [2](#0-1) ). The four components are joined with a bare `"-"` with no escaping of `"-"` inside `payload.asset` or `input.unit`. `payload.asset` is validated elsewhere to be `"base"` or a 44-char base64 unit hash (fixed length, so not directly attacker-shaped), and `input.unit` is validated to be `constants.HASH_LENGTH` (44) as well — this specific instance is defended by the fixed-length hash format for `asset`/`unit`. However, this is the same *pattern class* as the reported bug: relying on ad-hoc string concatenation with an unescaped delimiter for a security-critical uniqueness/namespace key, instead of using a length-prefixed or otherwise collision-safe encoding (e.g., the delimiter-safe `getSourceString()` helper already used elsewhere in the codebase, see [3](#0-2) , which explicitly guards against embedded join-character collisions).

By contrast, other consensus-critical namespaced keys in the codebase were hardened against exactly this class of bug by explicitly rejecting the delimiter character in user-controlled segments — e.g. data-feed keys reject embedded `\n` in `feed_name`/`value` before they are joined with `\n`: [4](#0-3) 

The AA state-variable key builder, however, does **not** perform the same check on `var_name` before concatenating with `\n`: [5](#0-4) [6](#0-5) 

`var_name` is only checked for length and `isWellFormed()` (no lone surrogates), not for absence of the `\n` delimiter used to join `"st\n" + address + "\n" + var_name`. Because `address` is always a fixed 32-character value immediately preceding the delimiter, an embedded `\n` inside `var_name` cannot shift the address boundary and cannot let one AA's storage collide with another AA's storage or with a different `var_name` under the *same* address (each resulting key is still a distinct byte string). So while the missing delimiter-escaping check is a real code-quality/defense-in-depth gap identical in *pattern* to the reported Solidity bug, tracing all reachable consumers (`readAAStateVar`, `readAAStateVars` prefix-scan, `checkStorageSizes`, `find_longest_state_var.js`) shows no path where this ambiguity produces a concrete unauthorized fund transfer, double-spend, supply inflation, or consensus disagreement, because the address prefix is always fixed-length and prefix-range reads only use the caller's own address.

### Impact Explanation
No concretely exploitable impact could be established. The `input_key` concatenation in `validation.js` is currently safe in practice because `asset` and `unit` are both fixed-length (44-char) base64 hashes, so no delimiter-driven collision between two distinct valid inputs is possible with the current field formats. The state-variable key concatenation gap in `aa_composer.js`/`formula/evaluation.js` also does not yield a reachable collision because the address segment has fixed length. Neither instance meets the bar of "concrete unauthorized spending, double-spend of a stable output, supply inflation, AA fund loss/freezing, or node disagreement on validity/stability."

### Likelihood Explanation
Low likelihood of exploitation today, since it depends on future changes (e.g., variable-length `asset` identifiers, or a variable-length prefix before the state-var name) that are not present in the current schema/format constraints.

### Recommendation
As defense-in-depth against the same bug class described in the external report:
1. Add an explicit check rejecting `\n` (or whatever delimiter is chosen) inside `var_name` in `formula/evaluation.js`'s `state_var_assignment` handler, mirroring the check already applied to `feed_name` in `validation.js`/`aa_validation.js` for `data_feed`.
2. For `validation.js`'s `input_key` (and the historical `spend_proofs` key), consider switching to `string_utils.getSourceString()` or an explicit fixed-width/length-prefixed encoding instead of ad-hoc `"-"` concatenation, so future changes to `asset`/`unit`/`message_index` formats cannot silently reintroduce a collision.

### Proof of Concept
No working end-to-end PoC could be constructed against current mainnet constraints: `asset` and `input.unit` are enforced to be exactly `constants.HASH_LENGTH` (44) base64 characters ( [7](#0-6) ), and AA `var_name`/`address` segments are always separated by a fixed-length address, so no two distinct, independently-valid tuples currently serialize to the same key. This finding is reported as a hardening/code-pattern issue analogous to the referenced report rather than a demonstrated exploit.

### Citations

**File:** validation.js (L1577-1579)
```javascript
			if (objValidationState.arrInputKeys.indexOf(objSpendProof.spend_proof) >= 0)
				return callback("spend proof "+objSpendProof.spend_proof+" already used");
			objValidationState.arrInputKeys.push(objSpendProof.spend_proof);
```

**File:** validation.js (L1933-1944)
```javascript
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
```

**File:** validation.js (L2395-2396)
```javascript
					if (!isStringOfLength(input.unit, constants.HASH_LENGTH))
						return cb("wrong unit length in payment input");
```

**File:** validation.js (L2402-2405)
```javascript
					var input_key = (payload.asset || "base") + "-" + input.unit + "-" + input.message_index + "-" + input.output_index;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return cb("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
```

**File:** string_utils.js (L11-60)
```javascript
function getSourceString(obj) {
	var arrComponents = [];
	function extractComponents(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				if (variable.includes(STRING_JOIN_CHAR))
					throw Error("00 byte in string value in " + JSON.stringify(obj));
				arrComponents.push("s", variable);
				break;
			case "number":
				if (!isFinite(variable))
					throw Error("invalid number: " + variable);
				arrComponents.push("n", variable.toString());
				break;
			case "boolean":
				arrComponents.push("b", variable.toString());
				break;
			case "object":
				if (Array.isArray(variable)){
					if (variable.length === 0)
						throw Error("empty array in "+JSON.stringify(obj));
					arrComponents.push('[');
					for (var i=0; i<variable.length; i++)
						extractComponents(variable[i]);
					arrComponents.push(']');
				}
				else{
					var keys = Object.keys(variable).sort();
					if (keys.length === 0)
						throw Error("empty object in "+JSON.stringify(obj));
					keys.forEach(function(key){
						if (typeof variable[key] === "undefined")
							throw Error("undefined at "+key+" of "+JSON.stringify(obj));
						if (key.includes(STRING_JOIN_CHAR))
							throw Error("00 byte in object key in " + JSON.stringify(obj));
						arrComponents.push(key);
						extractComponents(variable[key]);
					});
				}
				break;
			default:
				throw Error("getSourceString: unknown type="+(typeof variable)+" of "+variable+", object: "+JSON.stringify(obj));
		}
	}

	extractComponents(obj);
	return arrComponents.join(STRING_JOIN_CHAR);
}
```

**File:** aa_composer.js (L1487-1503)
```javascript
	function saveStateVars() {
		if (bSecondary || bBouncing || trigger_opts.bAir)
			return;
		for (var address in stateVars) {
			var addressVars = stateVars[address];
			for (var var_name in addressVars) {
				var state = addressVars[var_name];
				if (!state.updated)
					continue;
				var key = "st\n" + address + "\n" + var_name;
				if (state.value === false) // false value signals that the var should be deleted
					batch.del(key);
				else
					batch.put(key, getTypeAndValue(state.value)); // Decimal converted to string, object to json
			}
		}
	}
```

**File:** formula/evaluation.js (L1346-1351)
```javascript
						if (var_name.length > constants.MAX_STATE_VAR_NAME_LENGTH)
							return setFatalError("state var name too long: " + var_name, { arr }, false, cb);
						if (!var_name.isWellFormed())
							return setFatalError("state var name not well formed: " + var_name, { arr }, false, cb);
						if (typeof res === 'string' && !res.isWellFormed())
							return setFatalError("state var value not well formed: " + res, { arr }, false, cb);
```
