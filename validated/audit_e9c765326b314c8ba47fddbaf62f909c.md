## Title
Uncaught exception in `definition template` authentifier evaluation crashes ocore full node - ([File: definition.js])

### Summary
`definition.js`'s `validateAuthentifiers()` handles the `'definition template'` operator (used inside an address definition, e.g. `['definition template', [unit, params]]`) by fetching the referenced `definition_template` message, JSON-parsing it, and calling `replaceInTemplate(arrTemplate, params)` with **no try/catch** around it, unlike the equivalent code path in `validateDefinition()` which wraps the same call in try/catch (albeit only gracefully handling `NoVarException`). [1](#0-0) [2](#0-1) 

### Finding Description
An unprivileged user can create an address whose definition contains `['definition template', [template_unit, params]]`, and separately post an ordinary `definition_template` message in a unit (`template_unit`). This app is only lightly validated: `validateInlinePayload` merely checks `isArrayOfLength(payload, 2)` with no constraint on the template's structure or the variable names it uses. [3](#0-2) [4](#0-3) 

At definition-creation time, `validateDefinition()`'s `'definition template'` handler only requires each param value to be a string or number and that the referenced unit contains exactly one `definition_template` message — it does not check that the params actually match the variable placeholders (`$name`) used inside the template body. [5](#0-4) 

Later, whenever a unit actually spends from (signs with) that address, `validateAuthentifiers()` re-evaluates the definition to check signatures, hitting the same `'definition template'` case — but this code path calls `replaceInTemplate()` **without any try/catch**:
```
case 'definition template':
    ...
    conn.query(..., function(rows){
        if (rows.length !== 1)
            throw Error("not 1 template");
        var template = rows[0].payload;
        var arrTemplate = JSON.parse(template);
        var arrFilledTemplate = replaceInTemplate(arrTemplate, params);   // can throw NoVarException uncaught
        evaluate(arrFilledTemplate, path, cb2);
    });
    break;
``` [1](#0-0) 

`replaceInTemplate()` throws a `NoVarException` (a plain thrown object, not a caught error) whenever a `$name` placeholder in the template is not present in `params`: [2](#0-1) 

Since this call site has no catch handler, the exception propagates up through `validateAuthentifiers` → `validateAuthor` → `validate()` → the async chain in `mutex.lock(...)`, becoming an unhandled exception in the event loop (it is thrown asynchronously inside a DB-query callback, so it cannot be caught even by an outer try/catch in the caller). ocore installs a global `process.on('uncaughtException', ...)` handler that deliberately **re-throws** to crash the process "to avoid ending up in an inconsistent state": [6](#0-5) 

This mirrors the Envoy CVE-2022-21655 bug class precisely: two independently valid-looking configuration elements (a route referencing internal-redirect behavior; here, an address definition referencing a template) combine at evaluation time in a way that the code assumed couldn't happen, and the missing defensive check on that particular path (present in the sibling `validateDefinition` path but omitted in `validateAuthentifiers`) triggers a crash instead of a graceful validation error.

### Impact Explanation
Any node (full node) that validates a spending unit for such a maliciously-crafted address will hit the unguarded `throw` and crash via the global `uncaughtException` handler. Because the crash is deterministic given the same address/definition/spending-unit combination, any full node (miner/hub/relay) that processes this unit will crash identically. This is a network-wide denial-of-service: the malicious unit, once broadcast, can crash every full node that attempts to validate it, making the network unable to confirm new units and process transactions until the code is patched — satisfying the "network unable to confirm new units" impact bar.

### Likelihood Explanation
The attack requires no special privilege: any user can (1) post a `definition_template` message, and (2) create/fund an address whose definition uses `['definition template', [unit_of_that_message, params]]` with `params` intentionally missing one of the `$name` variables actually referenced inside the template body (the pre-creation check at `definition.js:306-343` does not verify the params against the template's variable names — it only checks the params values, not the template content, since the template's message may not even be known/decoded at that validation stage, or may be crafted to only reveal the mismatch when a specific inner branch of the template — e.g. an `and`/`or` — is evaluated). Once the address is funded and any unit signs with the affected `definition template` authentifier path, `validateAuthentifiers` is invoked by every node validating that unit, triggering the uncaught `NoVarException` and crash.

### Recommendation
Wrap the `replaceInTemplate()` call inside `validateAuthentifiers`'s `'definition template'` case (`definition.js:815`) in a try/catch identical to the one already used in `validateDefinition` (`definition.js:330-339`), converting `NoVarException` (and any other exception) into a normal validation failure (`cb2(false)` or an error passed to `cb`) instead of letting it propagate as an uncaught exception. Additionally, consider validating at `definition_template` message-creation time, or at address `definition template` reference time, that all `$name` placeholders used in the template are covered by allowed params, to close this class of runtime mismatch.

### Proof of Concept
1. Attacker posts unit `U1` containing a `definition_template` message whose payload is, e.g., `['and', [['sig', {pubkey: '$pubkey'}], ['in data feed', ['$oracle'], '$feed', '=', '$value']]]` (uses variables `$pubkey`, `$oracle`, `$feed`, `$value`).
2. Attacker creates address `A` with definition `['definition template', [U1_unit_hash, {pubkey: 'BASE64PUBKEY'}]]` — deliberately omitting `oracle`, `feed`, `value` from `params`. The pre-check in `validateDefinition` (`definition.js:306-343`) only checks that `params` values are strings/numbers and that exactly one `definition_template` message exists at `U1` — it does not check that all variables used by the template are supplied, so this passes.
3. Attacker funds `A` and later posts a spending unit `U2` authored by `A` with a signature authentifier.
4. Every node validating `U2` calls `validateAuthentifiers`, which re-evaluates `A`'s definition, hits `'definition template'`, calls `replaceInTemplate(arrTemplate, {pubkey: ...})`. Since `oracle`/`feed`/`value` are referenced by `$name` in the template but absent from `params`, `replaceInVar` throws `NoVarException` uncaught (`definition.js:1479-1480`), which is not caught anywhere in the async call chain of `definition.js:802-819`.
5. The uncaught exception reaches `process.on('uncaughtException', ...)` in `network.js:4530-4543`, which re-throws and crashes the node process — reproducibly, on every full node that validates `U2`.

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

**File:** definition.js (L1468-1495)
```javascript
function replaceInTemplate(arrTemplate, params){
	function replaceInVar(x){
		switch (typeof x){
			case 'number':
			case 'boolean':
				return x;
			case 'string':
				// searching for pattern "$name"
				if (x.charAt(0) !== '$')
					return x;
				var name = x.substring(1);
				if (!ValidationUtils.hasOwnProperty(params, name))
					throw new NoVarException("variable "+name+" not specified, template "+JSON.stringify(arrTemplate)+", params "+JSON.stringify(params));
				return params[name]; // may change type if params[name] is not a string
			case 'object':
				if (Array.isArray(x))
					for (var i=0; i<x.length; i++)
						x[i] = replaceInVar(x[i]);
				else
					for (var key in x)
						assignField(x, key, replaceInVar(x[key]));
				return x;
			default:
				throw Error("unknown type");
		}
	}
	return replaceInVar(_.cloneDeep(arrTemplate));
}
```

**File:** validation.js (L2003-2009)
```javascript
		case "definition_template":
			if (objValidationState.bHasDefinitionTemplate)
				return callback("can be only one definition template");
			objValidationState.bHasDefinitionTemplate = true;
			if (!ValidationUtils.isArrayOfLength(payload, 2))
				return callback(objMessage.app+" payload must be array of two elements");
			return callback();
```

**File:** aa_validation.js (L425-429)
```javascript
				case 'definition_template':
					if (!ValidationUtils.isArrayOfLength(payload, 2))
						return cb2("AA definition_template must be array of two elements");
					cb2();
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
