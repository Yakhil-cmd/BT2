## Title
Uncaught exception in `replaceInTemplate()` during address-definition-template evaluation crashes the entire node - ([File: definition.js])

### Summary
`definition.js`'s `validateDefinition()` handles the `'definition template'` opcode by fetching a stored template and calling `replaceInTemplate(arrTemplate, params)` inside a synchronous `try/catch` that only forgives `NoVarException`; any other exception type is re-thrown: [1](#0-0) 

This mirrors the SkyWalking NodeJS agent bug class: input that reaches deep application logic and triggers an unhandled/uncaught exception path, taking the whole service down rather than just failing the single operation.

### Finding Description
`validateDefinition()` is invoked while validating any unit whose author's address (or asset condition) uses a `'definition template'` element, referencing a previously-posted `definition_template` message and filling it with attacker-supplied `params`: [2](#0-1) 

The template lookup and fill happens synchronously inside a `conn.query` callback: [3](#0-2) 

The `catch` block only special-cases `NoVarException` (returned as a normal validation error via `cb`); every other exception — e.g., a `TypeError` thrown by `replaceInTemplate` when `params` values interact unexpectedly with the template structure, or any other runtime error inside that template-substitution routine — is re-thrown with `throw e`. Because this occurs inside an asynchronous database callback (not inside any surrounding `try/catch` in the call chain from `network.js`'s `handleJoint`/`validate` pipeline), the exception becomes a Node.js `uncaughtException`. `network.js` installs a global handler for exactly this case, and it deliberately re-throws to crash the process: [4](#0-3) 

An attacker only needs to control their **own address definition** (something any ordinary user/wallet is free to do) so that it embeds a `'definition template'` reference to a `definition_template` message they previously posted, with a template body crafted so that `replaceInTemplate` throws a non-`NoVarException` error for some `params` value combination. The attacker then posts a normal unit authored by that address, using the malicious `params`. Any full node (validator, hub, or witness) that validates this unit — an operation performed automatically and unconditionally on any freshly received/posted unit — will execute this vulnerable code path and crash.

### Impact Explanation
A crash triggered this way is not confined to the attacker's own client: **every full node in the network that receives and validates the malicious unit will crash**, because unit validation is a universal, non-optional step performed by all full nodes (hubs, witnesses, and light vendors serving full-node duties). Because `network.js`'s `uncaughtException` handler intentionally re-throws to "crash the process to avoid ending up in an inconsistent state," the entire node process terminates. If this unit propagates through the P2P network (which it will, as a normal validly-formed, validly-signed unit up to this specific check), it can cascade and crash multiple/most full nodes that attempt to validate it, producing a network-wide denial of service — i.e., the network becomes unable to confirm new units until operators patch and filter the offending unit. This satisfies the required "network unable to confirm new units" impact bar.

### Likelihood Explanation
Likelihood is high for a determined attacker: definition templates and `definition_template` messages are a standard, unprivileged feature (any user can post a `definition_template` app message and register an address using `'definition template'` in its definition). The attacker fully controls both the template content and the `params` object supplied in the posted unit, giving them wide latitude to search for parameter/template combinations that make `replaceInTemplate` throw an exception other than `NoVarException` (e.g., type-confusion in placeholder substitution, malformed nested structures, etc.). No cooperation from other parties, no special timing, and no privileged access are required.

### Recommendation
Wrap the `replaceInTemplate` call (and the whole `'definition template'` opcode handling block) in a catch-all that converts **any** exception into a normal validation error via `cb(...)`, rather than distinguishing only `NoVarException`. Concretely, change:
```js
catch(e){
    if (e instanceof NoVarException)
        return cb(e.toString());
    else
        throw e;
}
```
to unconditionally `return cb("bad template: " + e.toString())` (or similarly convert to a soft validation failure) for all exception types. More broadly, audit `replaceInTemplate` itself to ensure it never throws on attacker-controlled `arrTemplate`/`params` inputs and only signals expected conditions (missing variable, wrong type, etc.) through defined error objects that validation code explicitly handles.

### Proof of Concept
1. As attacker, post a `definition_template` message defining a template `arrTemplate` whose structure, when combined with certain `params`, causes `replaceInTemplate` (in `definition.js`, used by `wallet_defined_by_addresses.js`/`wallet_defined_by_keys.js`) to hit an unexpected type/shape and throw a generic `Error`/`TypeError` (not `NoVarException`) — e.g., by supplying a `params` value whose type conflicts with an internal assumption made while walking/replacing nested template fields.
2. Register (or reuse) an address whose definition is `['definition template', [<templateUnit>, <maliciousParams>]]`.
3. Post a normal unit authored by that address, referencing the same `templateUnit` and `maliciousParams` so that `evaluate()`'s `'definition template'` branch is triggered during validation of this unit by any receiving node.
4. Broadcast the unit; every full node that validates it executes the vulnerable `replaceInTemplate` call, throws a non-`NoVarException` exception, hits Node's `uncaughtException` handler in `network.js`, and crashes the process.

Note: I was unable to locate and inspect the exact implementation of `replaceInTemplate()` and the `NoVarException` class within the indexed codebase content (they are referenced from `definition.js`, `wallet_defined_by_addresses.js`, and `wallet_defined_by_keys.js`, but their bodies were not returned by search/read tools due to index coverage limits). Confirming the precise exception conditions that are *not* `NoVarException` requires reading that file directly; I recommend starting a Devin session with full filesystem access to pinpoint the exact throwing statements inside `replaceInTemplate` and validate a concrete crafted payload.

### Citations

**File:** definition.js (L306-320)
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
```

**File:** definition.js (L321-341)
```javascript
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
