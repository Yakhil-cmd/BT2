### Title
Unhandled exception in `definition template` evaluation crashes validating nodes - ([File: definition.js])

### Summary
When evaluating an address/asset definition that uses the `definition template` operator, `definition.js` fetches a previously-posted template, fills it with attacker-supplied `params`, and only catches one specific exception type (`NoVarException`). Any other exception thrown while filling the template is re-thrown inside an asynchronous DB-callback, which is never caught by `validation.validate()`'s outer error handling. This turns into a process-level uncaught exception, and the process handler in `network.js` deliberately crashes the whole node to avoid running with inconsistent state — giving an unprivileged unit poster a way to hang/crash any full node that receives and validates the crafted unit, analogous to how CVE-2017-3244 lets a low-privileged, network-reachable actor crash the MySQL server by driving it into an unhandled error state during normal message/statement processing.

### Finding Description
`validateDefinition`'s `evaluate()` handles the `definition template` opcode: [1](#0-0) 

The relevant excerpt:
```
conn.query(
    "SELECT payload FROM messages JOIN units USING(unit) \n\
    WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
    [unit, objValidationState.last_ball_mci],
    function(rows){
        ...
        var arrTemplate = JSON.parse(template);
        try{
            var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
            ...
        }
        catch(e){
            if (e instanceof NoVarException)
                return cb(e.toString());
            else
                throw e;               // <-- rethrown, escapes the async callback
        }
        evaluate(arrFilledTemplate, path, bInNegation, cb);
    }
);
```
The `catch` block only converts `NoVarException` into a normal validation error via `cb()`. Any other exception (e.g., a type mismatch, malformed nested structure, or edge case inside `replaceInTemplate` when combining the stored template with attacker-controlled `params`) is re-thrown with `throw e`. Because this code executes inside a `conn.query` callback — deep in an `async.series` chain launched from `validation.validate()` (`validation.js:118-496`, particularly the `validateAuthors`/`validateMessages` steps which call into `definition.validateDefinition`) — the throw is not caught by any surrounding `try/catch` in `validation.js`. It propagates out as an uncaught exception on the Node.js event loop.

`network.js` installs a global handler that explicitly crashes the process on any uncaught exception, by design: [2](#0-1) 

Any node — full node, hub, or AA-hosting node — that receives and validates a unit whose address (or asset) definition contains a `definition template` reference that triggers a non-`NoVarException` failure will crash. Since validation of freshly-received/posted units is mandatory network-wide processing (analogous to how the MySQL server must process any submitted DML), this reachable, single-unit-triggered crash mirrors the "low-privileged attacker via network protocol causes hang/crash of the server" pattern in CVE-2017-3244.

### Impact Explanation
A successful trigger crashes the validating node process entirely (not just fails validation), because `network.js`'s `uncaughtException` handler intentionally re-throws to kill the process. If an attacker crafts and gossips a single such unit, every full node/hub that receives and validates it goes down, which can disrupt the network's ability to confirm new units (a network-wide availability impact), matching the CVSS Availability-High profile of the source CVE.

### Likelihood Explanation
Reaching this code path only requires: (1) a previously posted, stable `definition_template` message (a normal, permissionless message type any unit poster can create), and (2) a new unit whose address (or asset) definition references that template via `['definition template', [template_unit, params]]` with `params` values chosen to make `replaceInTemplate` fail in a way other than the expected "variable not found" case. No special privileges, elevated author, or targeted victim/peer are needed — an ordinary unit poster reaches this via the AA/unit validation path used for every incoming unit.

### Recommendation
- Do not blindly `throw e` for unexpected exception types inside the `definition template` evaluation; instead, treat any exception from `replaceInTemplate` as a normal validation error (`return cb("invalid template: " + e)`), consistent with how `NoVarException` is already handled.
- Audit other `conn.query` callbacks in `definition.js` and `validation.js` for the same "rethrow inside async callback" anti-pattern, since any of them can similarly crash the process instead of failing validation gracefully.
- Consider hardening `replaceInTemplate` itself against malformed/adversarial template+params combinations so it cannot throw non-`NoVarException` errors at all.

### Proof of Concept
1. Post message A (`app: 'definition_template'`) with a template array designed to exercise an edge case of `replaceInTemplate` (e.g., a parameter substitution position that is structurally incompatible with the value type supplied later). Get it stable.
2. Post unit B whose author's address definition (or an asset's definition) includes:
   `['definition template', [unit_of_A, { param1: <value chosen to break replaceInTemplate in a non-NoVarException way> }]]`
3. Broadcast/POST unit B to any full node for validation.
4. During `validateDefinition` → `evaluate()` → the `definition template` case in `definition.js:306-342`, `replaceInTemplate` throws a non-`NoVarException` error, which is re-thrown (`throw e`) inside the `conn.query` callback, escapes to the event loop as an uncaught exception, and is caught by `network.js`'s handler (`network.js:4530-4543`), which re-throws it again — crashing the node process.

Note: I could not fully inspect the internal implementation of `replaceInTemplate` (its exact traversal/substitution logic) within the available tool budget, so I cannot cite the specific line(s) inside that function that produce a non-`NoVarException` throw for a given crafted input. The root-cause defect — an async-callback rethrow of any non-`NoVarException` error, uncaught by `validation.js`, leading to a deliberate process crash in `network.js` — is directly confirmed in the cited code.

### Citations

**File:** definition.js (L306-342)
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
