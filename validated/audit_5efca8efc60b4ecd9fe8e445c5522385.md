### Title
Uncaught `throw` in `definition template` authentifier evaluation crashes the node - ([File: definition.js])

### Summary
`definition.js`'s `evaluate()` function used during signature/authentifier validation (`validateAuthentifiers`) handles the `'definition template'` operator by querying the `messages`/`units` tables for a `definition_template` message and asserting exactly one row is returned. If that assertion fails, the code does `throw Error("not 1 template")` inside an asynchronous `conn.query()` callback with no surrounding `try/catch`. [1](#0-0) 

### Finding Description
When an address's spending definition contains the `'definition template'` operator, every time that address signs a unit, `validateAuthentifiers` walks the definition tree and re-evaluates this branch: [1](#0-0) 
```
case 'definition template':
    var unit = args[0];
    var params = args[1];
    conn.query(
        "SELECT payload FROM messages JOIN units USING(unit) \n\
        WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
        [unit, objValidationState.last_ball_mci],
        function(rows){
            if (rows.length !== 1)
                throw Error("not 1 template");
            ...
```
Unlike the sibling code path that validates the *syntax* of a fresh definition (`validateDefinition`'s own `'definition template'` handling, which gracefully returns `cb("template not found or too many")` and additionally wraps template-filling in `try/catch`) [2](#0-1) , the authentifier-evaluation code path that runs on *every subsequent signature check* for that address has no such protection — it throws synchronously from inside a DB callback.

This throw is not caught anywhere up the call chain (`validateAuthentifiers` → `validateAuthor` → `validateAuthors` → `validate`), so it propagates out of the async db callback as an uncaught exception. `network.js` installs a global handler that explicitly re-throws to crash the process rather than let the node continue in an inconsistent state: [3](#0-2) 

The row-count assumption (`rows.length === 1`) that held true when the address definition was first validated is not guaranteed to still hold every time the address is later used to sign a unit, because the underlying `messages` row for the referenced `unit` can disappear or duplicate between validations (e.g. via archiving/pruning of old unit content, which deletes rows from the `messages` table, as referenced by the `DELETE FROM messages WHERE unit...` operations in `archiving.js`). Any full node that has pruned/archived a unit previously used as a `'definition template'` reference — or any node whose local state diverges even transiently from another node's view of that row — hits `rows.length !== 1` and crashes with an uncaught exception on the next signature check for that address, rather than returning a validation error.

### Impact Explanation
A crash triggered from ordinary unit/signature validation is a genuine Denial-of-Service against a full node: the process dies (`process.on('uncaughtException')` re-throws by design), interrupting validation and propagation of new units for that node. Because `'definition template'` addresses can be defined and reused by any unprivileged wallet, and archiving/pruning of old unit content is a normal, non-privileged occurrence in ocore's operation, this reachable crash meets the "network unable to confirm new units" criterion for affected nodes — analogous to the libnbd CVE-2023-5871 pattern where malformed/unexpected server data causes an unhandled crash in the client parser.

### Likelihood Explanation
Likelihood is moderate: it requires (1) an address definition using `'definition template'` referencing another unit's `definition_template` message, and (2) that referenced message's row becoming unavailable or duplicated relative to when the definition was first accepted (e.g., due to archiving of old content or divergent local pruning state) at the time a later signature by that address is checked. This does not require any special privilege — only ordinary address/definition usage plus normal node housekeeping (pruning/archiving) — and no attacker-side race is strictly necessary once such a mismatch occurs naturally on any node running archiving.

### Recommendation
Replace the `throw Error("not 1 template")` in the `'definition template'` branch of the authentifier-evaluation `evaluate()` function in `definition.js` with a graceful failure via the `cb2` callback (e.g., `return cb2(false)` or an explicit validation error), matching the safer handling already used in the definition-syntax-validation code path. Additionally audit all other synchronous `throw` statements inside asynchronous `conn.query` callbacks in `definition.js`'s two `evaluate()` implementations (e.g. `"more than 1 address definition"`, `"not 1 template"` in `validateDefinition`'s cousin at line ~812) to ensure none can be reached from data that is not fully re-verified at validation time, or wrap those callbacks in `try/catch` that funnel into `cb`/`cb2` error paths instead of throwing.

### Proof of Concept
Conceptual reproduction (would need to be validated on a running node/testnet):
1. Post unit `U` containing a `definition_template` app message with valid `payload` (a definition template array).
2. Define an address `X` whose spending definition is `['definition template', [U, {...params}]]`; this passes `validateDefinition`'s syntax check while `U`'s message row is present and stable.
3. Trigger normal archiving/pruning of `U`'s content on a full node (or otherwise cause the `messages` row for `U`/`app='definition_template'` to no longer satisfy the query's `WHERE` conditions, e.g. row deleted or duplicated).
4. Have address `X` sign any new unit. During `validateAuthentifiers`, the `'definition template'` branch's `conn.query` callback re-checks `rows.length !== 1`; if it fails, it executes `throw Error("not 1 template")` inside the async callback, which is uncaught and crashes the node process via the global `uncaughtException` handler in `network.js`.

### Citations

**File:** definition.js (L306-343)
```javascript
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isArrayOfLength(args, 2))
					return cb("2-element array expected in "+op);
				var unit = args[0];
				var params = args[1];
				if (!isValidBase64(unit, constants.HASH_LENGTH))
					return cb("unit must be a valid base64 string 44 bytes long");
				if (!isNonemptyObject(params))
					return cb("params must be non-empty object");
				for (var key in params)
					if (typeof params[key] !== "string" && typeof params[key] !== "number")
						return cb("each param must be string or number");
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							return cb("template not found or too many");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						try{
							var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
							console.log(require('util').inspect(arrFilledTemplate, {depth: null}));
						}
						catch(e){
							if (e instanceof NoVarException)
								return cb(e.toString());
							else
								throw e;
						}
						evaluate(arrFilledTemplate, path, bInNegation, cb);
					}
				);
				break;
```

**File:** definition.js (L802-819)
```javascript
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				var unit = args[0];
				var params = args[1];
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							throw Error("not 1 template");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
						evaluate(arrFilledTemplate, path, cb2);
					}
				);
				break;
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
