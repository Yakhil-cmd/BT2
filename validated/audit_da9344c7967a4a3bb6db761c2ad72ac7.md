### Title
State-var storage size accounting uses UTF-16 character count instead of byte count, allowing AAs to under-report storage size and desynchronize byte_balance accounting - ([File: aa_composer.js])

### Summary
`aa_composer.js`'s `getValueSize()` computes the "size" of an AA state variable using JavaScript's `String#length` (UTF-16 code unit count) rather than the actual UTF-8 byte length that will be persisted and paid for. This is directly analogous to the reported Rack bug, where `Content-Length` was computed with `String#size` (char count) instead of `String#bytesize`, causing declared size to diverge from actual bytes.

### Finding Description
`getValueSize()` returns `value.length` for strings, and `getJsonSourceString(...).length` for wrapped JSON objects, then this value feeds `delta_storage_size` and ultimately `storage_size`, which is compared against the AA's `byte_balance`: [1](#0-0) [2](#0-1) 

`String#length` in JavaScript counts UTF-16 code units, not bytes. For any state-variable value containing multi-byte UTF-8 characters (e.g., non-ASCII text, emoji), the character count under-reports the true number of bytes that will actually be stored in the `storage_size`/DB accounting versus what the oscript `length()` operator and the rest of the system otherwise assume is a byte-equivalent size measure (`formula/evaluation.js`, case `'length'`, similarly uses `res.toString().length`) [3](#0-2) . Similarly, `MAX_AA_STRING_LENGTH` and `MAX_STATE_VAR_VALUE_LENGTH` enforcement in `aa_validation.js` and `aa_composer.js` are also based on character count, not byte count: [4](#0-3) 

This means an AA trigger author can craft state-variable values (via bounce messages/formula results) with multi-byte UTF-8 characters so that the accounted `storage_size` is systematically smaller than the number of bytes that are actually stored in the database. Since `updateStorageSize()` gate-checks `byte_balance < new_storage_size` to prevent an AA from paying for storage it can't afford [5](#0-4) , an attacker-influenced payload can make the AA store more real bytes than the size accounting believes, letting the check under-count consumed storage relative to actual usage.

### Impact Explanation
This causes a systemic accounting drift between the byte-cost model used to gate AA storage growth (`byte_balance` vs `storage_size`) and the actual bytes persisted for state vars. Over many operations with multi-byte content, an AA's `storage_size` bookkeeping in the `aa_addresses` table becomes permanently understated relative to real usage, letting an attacker force an AA to accumulate more actual storage than its `byte_balance` should allow, which can eventually contribute to AA fund exhaustion/freezing when the AA's true resource consumption outpaces what its tracked byte accounting reflects (falls under "AA fund loss or freezing").

### Likelihood Explanation
Likelihood is limited: any unprivileged unit poster can trigger AAs and can supply string arguments/state values containing multi-byte characters. However, the drift per character is small (JS strings for BMP characters already count 1 unit per character; only surrogate-pair/astral characters or truly multi-byte-heavy content increase the discrepancy meaningfully vs. UTF-8 byte counts), so the magnitude of exploitation is bounded per operation and would require repeated/large-scale abuse to produce material effect.

### Recommendation
Compute state-variable and JSON-source sizes using actual UTF-8 byte length (e.g., `Buffer.byteLength(value, 'utf8')`) in `getValueSize()` in `aa_composer.js`, and correspondingly in `variableHasStringsOfAllowedLength()` in `aa_validation.js` and the `'length'` operator handling in `formula/evaluation.js`, so that all size/length checks and storage-fee accounting consistently use byte counts rather than JavaScript string character counts.

### Proof of Concept
1. An AA (or bounce message) sets a state variable to a string containing many multi-byte UTF-8 characters, e.g. a string of astral-plane emoji (each 4 bytes in UTF-8, but only 2 UTF-16 code units in JS, i.e. `length === 2` per emoji).
2. `getValueSize()` computes `value.length`, undercounting the true UTF-8 byte size that will be written to storage.
3. `updateStorageSize()` uses this undercounted delta to update `storage_size` and compares it against `byte_balance`, permitting storage growth beyond what the AA's actual balance should allow relative to true bytes persisted.

Note: I was unable to fully trace how `storage_size` interacts with the on-disk column encoding (bytes vs characters) in `aa_addresses` across all DB backends (mysql/sqlite) within available context, so the exact magnitude of drift and whether the underlying JSON serialization in the database enforces byte-level truncation could not be fully confirmed from the indexed code alone.

### Citations

**File:** aa_composer.js (L1518-1529)
```javascript
	function getValueSize(value) {
		if (typeof value === 'string')
			return value.length;
		else if (typeof value === 'number')
			return value.toString().length;
		else if (Decimal.isDecimal(value))
			return value.toNumber().toString().length; // drop the excessive precision in subnormals
		else if (value instanceof wrappedObject)
			return string_utils.getJsonSourceString(value.obj, true).length;
		else
			throw Error("state var of unknown type: " + value);		
	}
```

**File:** aa_composer.js (L1552-1565)
```javascript
				if (newSize > constants.MAX_STATE_VAR_VALUE_LENGTH)
					return cb(`state var value too long: ${newSize}`);
				if (state.original_old_value !== undefined)
					delta_storage_size += newSize - getValueSize(state.original_old_value);
				else
					delta_storage_size += var_name.length + newSize;
			}
		}
		console.log('storage size = ' + storage_size + ' + ' + delta_storage_size + ', byte_balance = ' + byte_balance);
		var new_storage_size = storage_size + delta_storage_size;
		if (new_storage_size < 0)
			throw Error("storage size would become negative: " + new_storage_size);
		if (byte_balance < new_storage_size && new_storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci)
			return cb("byte balance " + byte_balance + " would drop below new storage size " + new_storage_size);
```

**File:** formula/evaluation.js (L1991-1998)
```javascript
					if (op === 'length'){
						if (res instanceof wrappedObject) {
							if (mci < constants.aa2UpgradeMci)
								res = true;
							else
								return cb(new Decimal(Array.isArray(res.obj) ? res.obj.length : Object.keys(res.obj).length));
						}
						return cb(new Decimal(res.toString().length));
```

**File:** aa_validation.js (L829-854)
```javascript
function variableHasStringsOfAllowedLength(x) {
	switch (typeof x) {
		case 'number':
		case 'boolean':
			return true;
		case 'string':
			return (x.length <= constants.MAX_AA_STRING_LENGTH);
		case 'object':
			if (Array.isArray(x)) {
				for (var i = 0; i < x.length; i++)
					if (!variableHasStringsOfAllowedLength(x[i]))
						return false;
			}
			else {
				for (var key in x) {
					if (key.length > constants.MAX_AA_STRING_LENGTH)
						return false;
					if (!variableHasStringsOfAllowedLength(x[key]))
						return false;
				}
			}
			return true;
		default:
			throw Error("unknown type " + (typeof x) + " of " + x);
	}
}
```
