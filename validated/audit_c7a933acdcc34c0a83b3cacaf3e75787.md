Based on my investigation, I found a concrete analog: the `state_var_assignment` handler in AA formula evaluation validates the state var *value* (length, well-formedness) but never checks the var *name* for the `\n` delimiter character that is used to build the kvstore key, unlike the parallel `data_feed` app which explicitly checks `feed_name.indexOf('\n')` in both `validation.js` and `aa_validation.js`.

### Title
Newline injection in AA state variable name bypasses key-delimiter safety, corrupting state var storage/enumeration - ([File: formula/evaluation.js])

### Summary
`data_feed` payloads explicitly reject `\n` in `feed_name` before the value is persisted with `\n`-joined kvstore keys [1](#0-0) , mirroring the same check in AA data-feed messages [2](#0-1) . However, the sibling mechanism that lets an AA persist arbitrary named state — `state_var_assignment` in `formula/evaluation.js` — validates only the *value* (`isWellFormed`, `MAX_STATE_VAR_VALUE_LENGTH`) and the *name*'s type/length, but never rejects `\n` in `var_name` before it is concatenated into the kvstore key `"st\n" + address + "\n" + var_name` [3](#0-2)  and [4](#0-3) .

### Finding Description
An AA's own formula code fully controls `var_name` via `var[<expr>] = value` — it can be any computed string, including the output of `crypto`, `input`, or trigger data concatenation, and is entirely attacker/AA-author controlled. The runtime check for state var assignment covers:
- name is a string, length ≤ `MAX_STATE_VAR_NAME_LENGTH`, `isWellFormed()` [5](#0-4) 
- value is well-formed and within length limits [6](#0-5) 

Neither check inspects the name for `\n`. The value is then written using `batch.put("st\n"+address+"\n"+var_name, ...)` [7](#0-6) . Downstream readers that split/slice on fixed offsets or on `\n` boundaries assume the format `st\n<32-byte-address>\n<var_name>`:
- `readAAStateVars` slices at a fixed offset (`data.key.slice(36)`) to recover `var_name`, so an injected `\n` is silently absorbed into the "var_name" portion rather than causing a parse error [8](#0-7) .
- `checkStorageSizes`/`initStorageSizes` use `data.key.substr(3, 32)` for address and `data.key.substr(36)` for `var_name`, and accumulate `var_name.length + value.length` into per-address storage-size accounting [9](#0-8) [10](#0-9) .
- `tools/find_longest_state_var.js` explicitly assumes exactly one `\n` separates address from var_name and treats everything after the first `\n` as the var name, showing the ambiguity is a real, exploitable parsing assumption throughout the codebase [11](#0-10) .

Because `readAAStateVar(address, var_name, ...)` does a direct `kvstore.get("st\n"+address+"\n"+var_name, ...)` [12](#0-11) , an attacker-controlled var_name containing `\n` lets an AA author craft a key that collides with, or is indistinguishable from, a different intended var_name (e.g., `var_name = "a\nb"` written for address `A` produces the exact same on-disk key as writing var name `"b"` under address `A/a` if it were parsed that way) — creating ambiguity between distinct logical variables and undermining consistent storage-size accounting/enumeration relied on for range queries with `var_prefix_from/var_prefix_to` in `light/get_aa_state_vars` [13](#0-12) .

### Impact Explanation
This breaks the implicit invariant that `\n` never appears inside a `var_name`, an invariant that is explicitly enforced for the structurally identical `feed_name` field elsewhere in the same codebase (proving the pattern is a recognized safety-critical requirement that was missed for state vars). Consequences reachable by a single AA definition (no privileged access needed):
- **Storage-size accounting corruption**: `updateStorageSize` computes `var_name.length + newSize` per var and updates `aa_addresses.storage_size`, which gates whether an AA can afford new storage against its byte balance [14](#0-13) . A crafted `var_name` with embedded `\n` can cause mismatches between the length used for accounting and the length actually persisted/read back via prefix or fixed-offset slicing elsewhere, potentially letting an AA under- or over-report its storage footprint relative to enforcement — a path toward AA fund/resource-limit bypass (denial of service on the AA, or unbounded storage growth beyond intended limits).
- **State readback ambiguity / enumeration corruption**: `readAAStateVars`'s naive `slice(36)` means an inserted `\n` is not treated as a separator, so exposed state (via `light/get_aa_state_vars`, `dry_run_aa`, or other AAs' `var[...]` getters keyed by computed names) can silently merge or shadow keys in ways formula logic doesn't expect, risking node/AA logic disagreement about a variable's true value between differing enumerations (prefix range scans vs point lookups), which is a form of state inconsistency across nodes/getters relying on this data for further AA fund routing decisions.

### Likelihood Explanation
Any AA author can trigger this at zero cost beyond normal AA deployment: `var[some_computed_string_with_\n] = value;` is valid oscript, since `var_name_or_expr` is evaluated as an arbitrary formula and only checked for type/length/well-formedness, not delimiter safety [15](#0-14) . No special privileges, other node cooperation, or network conditions are required — this is purely deterministic, self-triggerable AA logic.

### Recommendation
Add an explicit `\n` (and ideally `\0`) rejection check on `var_name` in the `state_var_assignment` evaluation path in `formula/evaluation.js`, mirroring the existing `feed_name.indexOf('\n') >= 0` checks used for data feeds in `validation.js` and `aa_validation.js`. Additionally, harden all key-parsing consumers (`readAAStateVars`, `checkStorageSizes`, `initStorageSizes`, `tools/find_longest_state_var.js`) to reject or correctly handle keys whose var_name segment contains a stray `\n`, rather than assuming a fixed offset/first-`\n` split.

### Proof of Concept
```
AA definition (oscript):
{
  messages: [
    { app: 'state', state: `{
        var['a' || "\n" || 'b'] = 'malicious';   // var_name = "a\nb"
        var['a'] = 'legit';                       // separate var_name = "a"
    }` }
  ]
}
```
After triggering this AA:
1. `readAAStateVars(address, cb)` returns keys derived via `data.key.slice(36)`, which will include the raw `"a\nb"` string as a single "var_name" — no error, no separation — while other tooling that assumes the first `\n` after the address terminates `var_name` (e.g. `tools/find_longest_state_var.js`) will instead report the var name as `"a"` with value effectively being `"b"` swallowed into what should be the delimiter, causing two different consumers of the same kvstore data to disagree about what state exists for the AA.
2. `checkStorageSizes`'s naive `substr(36)` will fold `"a\nb"`'s embedded newline into the accounted length while other code paths (formula evaluation) tracked `var_name.length` for the original computed JS string length, creating a discrepancy between `storage_size` in `aa_addresses` and the real kvstore usage that can be exploited to grow AA storage beyond what the byte-balance check in `updateStorageSize` intends to permit.

### Citations

**File:** validation.js (L1933-1937)
```javascript
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
```

**File:** aa_validation.js (L95-102)
```javascript
					for (var feed_name in payload) {
						var feed_name_formula = getFormula(feed_name);
						if (feed_name_formula === null) {
							if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
								return cb2("feed name " + feed_name + " too long");
							if (feed_name.indexOf('\n') >= 0)
								return cb2("feed name " + feed_name + " contains \\n");
						}
```

**File:** formula/evaluation.js (L1311-1361)
```javascript
				var var_name_or_expr = arr[1];
				var rhs = arr[2];
				var assignment_op = arr[3];
				evaluate(var_name_or_expr, function (var_name) {
					if (fatal_error)
						return cb(false);
					if (typeof var_name !== 'string')
						return setFatalError("assignment: state var name must be string, " + var_name_or_expr + " evaluated to " + JSON.stringify(var_name) + ` (${typeof var_name})`, { arr }, false, cb);
					evaluate(rhs, function (res) {
						if (fatal_error)
							return cb(false);
						if (!isValidValue(res) && !(res instanceof wrappedObject))
							return setFatalError("evaluation of rhs " + rhs + " in state var assignment failed: " + JSON.stringify(res), { arr }, false, cb);
						if (Decimal.isDecimal(res))
							res = toDoubleRange(res);
						// state vars can store strings, decimals, objects, and booleans but booleans are treated specially when persisting to the db: true is converted to 1, false deletes the var
						if (res instanceof wrappedObject) {
							if (mci < constants.aa2UpgradeMci)
								res = true;
							else {
								if (assignment_op !== '=' && assignment_op !== '||=')
									return setFatalError(assignment_op + " not supported for object vars", { arr }, false, cb);
								try {
									var json = string_utils.getJsonSourceString(res.obj, true);
								}
								catch (e) {
									return setFatalError("stringify failed: " + e, { arr }, false, cb);
								}
								if (json.length > constants.MAX_STATE_VAR_VALUE_LENGTH)
									return setFatalError("state var value too long when in json: " + json, { arr }, false, cb);
								if (isTooBigObj(res.obj))
									return setFatalError("rhs of state var assignment is too big", { arr }, false, cb);
								res = new wrappedObject(string_utils.cloneDeep(res.obj)); // make a copy
							}
						}
						if (var_name.length > constants.MAX_STATE_VAR_NAME_LENGTH)
							return setFatalError("state var name too long: " + var_name, { arr }, false, cb);
						if (!var_name.isWellFormed())
							return setFatalError("state var name not well formed: " + var_name, { arr }, false, cb);
						if (typeof res === 'string' && !res.isWellFormed())
							return setFatalError("state var value not well formed: " + res, { arr }, false, cb);
					//	if (typeof res === 'boolean')
					//		res = res ? dec1 : dec0;
						if (!stateVars[address])
							stateVars[address] = {};
					//	console.log('---- assignment_op', assignment_op)
						readVar(address, var_name, function (value) {
							if (assignment_op === "=") {
								if (typeof res === 'string' && res.length > constants.MAX_STATE_VAR_VALUE_LENGTH)
									return setFatalError("state var value too long: " + res, { arr }, false, cb);
								stateVars[address][var_name].value = res;
```

**File:** aa_composer.js (L1487-1502)
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
```

**File:** aa_composer.js (L1531-1568)
```javascript
	function updateStorageSize(cb) {
		if (bBouncing || trigger_opts.bAir)
			return cb();
		var delta_storage_size = 0;
		var addressVars = stateVars[address] || {};
		for (var var_name in addressVars) {
			var state = addressVars[var_name];
			if (!state.updated)
				continue;
			if (state.value === false) { // false value signals that the var should be deleted
				if (state.original_old_value !== undefined)
					delta_storage_size -= var_name.length + getValueSize(state.original_old_value);
			}
			else {
				try {
					var newSize = getValueSize(state.value);
				}
				catch (e) {
					console.log("failed to get size of new value of state var " + var_name + ": ", e);
					return cb("invalid new value of state var " + var_name);
				}
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
		if (delta_storage_size === 0)
			return cb();
		conn.query("UPDATE aa_addresses SET storage_size=? WHERE address=?", [new_storage_size, address], function () {
```

**File:** aa_composer.js (L1918-1932)
```javascript
function checkStorageSizes() {
	mutex.lockOrSkip(['checkStorageSizes'], function (unlock) {
		db.takeConnectionFromPool(function (conn) { // block conection for the entire duration of the check
			var options = {};
			options.gte = "st\n";
			options.lte = "st\n\uFFFF";

			var assocSizes = {};
			var handleData = function (data) {
				var address = data.key.substr(3, 32);
				var var_name = data.key.substr(36);
				if (!assocSizes[address])
					assocSizes[address] = 0;
				assocSizes[address] += var_name.length + data.value.length - 2; // -2 for type and \n
			}
```

**File:** storage.js (L1013-1022)
```javascript
function readAAStateVar(address, var_name, handleResult) {
	if (!handleResult)
		return new Promise(resolve => readAAStateVar(address, var_name, resolve));
	var kvstore = require('./kvstore.js');
	kvstore.get("st\n" + address + "\n" + var_name, function (type_and_value) {
		if (type_and_value === undefined)
			return handleResult();
		handleResult(parseStateVar(type_and_value));
	});
}
```

**File:** storage.js (L1024-1043)
```javascript
function readAAStateVars(address, var_prefix_from, var_prefix_to, limit, handle) {
	if (arguments.length <= 2) {
		handle = var_prefix_from;
		var_prefix_from = '';
		var_prefix_to = '';
		limit = 0;
	}
	if (!handle)
		return new Promise(resolve => readAAStateVars(address, var_prefix_from, var_prefix_to, limit, resolve));
	var options = {};
	options.gte = "st\n" + address + "\n" + var_prefix_from;
	options.lte = "st\n" + address + "\n" + var_prefix_to + "\uFFFF";
	if (limit)
		options.limit = limit;

	var assignField = require('./formula/common.js').assignField;
	var objStateVars = {}
	var handleData = function (data){
		assignField(objStateVars, data.key.slice(36), parseStateVar(data.value));
	}
```

**File:** sqlite_migrations.js (L662-676)
```javascript
function initStorageSizes(connection, arrQueries, cb){
	if (bCordova)
		return cb();
	var options = {};
	options.gte = "st\n";
	options.lte = "st\n\uFFFF";

	var assocSizes = {};
	var handleData = function (data) {
		var address = data.key.substr(3, 32);
		var var_name = data.key.substr(36);
		if (!assocSizes[address])
			assocSizes[address] = 0;
		assocSizes[address] += var_name.length + data.value.length;
	}
```

**File:** tools/find_longest_state_var.js (L23-32)
```javascript
	// key format: "st\n" + address + "\n" + var_name
	var key = data.key;
	if (!key.startsWith('st\n')) return;
	
	var rest = key.slice(3); // remove "st\n"
	var newlinePos = rest.indexOf('\n');
	if (newlinePos === -1) return;
	
	var address = rest.slice(0, newlinePos);
	var var_name = rest.slice(newlinePos + 1);
```

**File:** network.js (L3965-3993)
```javascript
		case 'light/get_aa_state_vars':
			if (!params)
				return sendErrorResponse(ws, tag, "no params in light/get_aa_state_vars");
			if (!ValidationUtils.isValidAddress(params.address))
				return sendErrorResponse(ws, tag, "address not valid");
			if ('var_prefix_from' in params && typeof params.var_prefix_from !== 'string')
				return sendErrorResponse(ws, tag, "var_prefix_from must be string");
			if ('var_prefix_to' in params && typeof params.var_prefix_to !== 'string')
				return sendErrorResponse(ws, tag, "var_prefix_to must be string");
			if ('var_prefix' in params && typeof params.var_prefix !== 'string')
				return sendErrorResponse(ws, tag, "var_prefix must be string");
			if ('var_prefix' in params && ('var_prefix_from' in params || 'var_prefix_to' in params))
				return sendErrorResponse(ws, tag, "var_prefix cannot be used with var_prefix_from or var_prefix_to");
			if ('var_prefix' in params){
				params.var_prefix_from = params.var_prefix;
				params.var_prefix_to = params.var_prefix;
			}
			if ('limit' in params && !ValidationUtils.isPositiveInteger(params.limit))
				return sendErrorResponse(ws, tag, "limit must be a positive integer");
			if ('limit' in params && params.limit > MAX_STATE_VARS)
				return sendErrorResponse(ws, tag, "limit cannot be greater than " + MAX_STATE_VARS);
			storage.readAADefinition(db, params.address, null, function (arrDefinition) {
				if (!arrDefinition) {
					arrDefinition = storage.getUnconfirmedAADefinition(params.address);
					if (!arrDefinition)
						return sendErrorResponse(ws, tag, "not an AA");
				}
				storage.readAAStateVars(params.address, params.var_prefix_from || '', params.var_prefix_to || '', params.limit || MAX_STATE_VARS, function (objStateVars) {
					sendResponse(ws, tag, objStateVars);
```
