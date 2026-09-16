### Title
Uncaught `NoVarException`/type error in `definition template` authentifier evaluation crashes all validating nodes - ([File: definition.js])

### Summary
Ocore's `process.on('uncaughtException', ...)` handler deliberately re-throws any uncaught exception to crash the node process, treating it as unrecoverable state corruption. [1](#0-0)  This mirrors the Tally VM bug class: an attacker-reachable code path that throws an uncaught error inside validation logic will crash every validating node that processes the malicious unit, causing a chain halt. In `definition.js`, the `'definition template'` opcode handler inside `validateAuthentifiers()` (used when checking signatures/authentifiers while **spending** from an address) calls `replaceInTemplate()` without any `try/catch`, unlike the equivalent code path in `validateDefinition()` (used when **defining** a new address) which explicitly catches the same exception. [2](#0-1) 

### Finding Description
An address can be defined using the `'definition template'` op, which references another unit's `definition_template` payload and fills it in with a fixed set of `params` chosen by the address owner at definition time:
```js
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
            var template = rows[0].payload;
            var arrTemplate = JSON.parse(template);
            var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
            evaluate(arrFilledTemplate, path, cb2);
        }
    );
    break;
``` [2](#0-1) 

`replaceInTemplate()` throws a `NoVarException` whenever the template references a `$varname` placeholder that is not present in the supplied `params` object, and throws a generic `Error("unknown type")` for unsupported value types:
```js
case 'string':
    if (x.charAt(0) !== '$')
        return x;
    var name = x.substring(1);
    if (!ValidationUtils.hasOwnProperty(params, name))
        throw new NoVarException(...);
    return params[name];
...
default:
    throw Error("unknown type");
``` [3](#0-2) 

The **only** other caller of the same template-filling logic, `validateDefinition()` (used when a brand-new address definition is checked, e.g. via `address_definition_change`), wraps the call in a `try/catch` and converts `NoVarException` into a normal validation error via `cb()`:
```js
try{
    var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
}
catch(e){
    if (e instanceof NoVarException)
        return cb(e.toString());
    else
        throw e;
}
``` [4](#0-3) 

But `validateAuthentifiers()` — invoked every time a unit is validated to check that its author's signature/authentifiers satisfy the address definition during a **spend** — has no such guard. [5](#0-4)  This function is reached from `validateAuthor()` in `validation.js`, which is on the mandatory path for every unit with a non-AA author (payments, AA triggers, etc.). [6](#0-5) 

An address's definition is fixed once created (or is immutable content the attacker fully controls at definition time), so an attacker can:
1. Post a `definition_template` unit whose template contains a `$var` placeholder.
2. Define (or use) an address whose spending definition is `['definition template', [template_unit, {/* missing $var */}]]`, deliberately omitting the variable from `params`.
3. Post any spending unit signed by that address.

When any validator (including all consensus-critical full/witness nodes) validates that spending unit, `validateAuthentifiers()` reaches the `'definition template'` case, calls `replaceInTemplate()`, hits the missing variable, and throws `NoVarException` uncaught. The exception bubbles up through the `async.eachSeries`/`conn.query` callback chain uncaught, eventually reaching Node's `uncaughtException` handler in `network.js`, which explicitly re-throws to crash the process. [1](#0-0) 

### Impact Explanation
Because every validating node (light and full, including witnesses) must run `validateAuthor` → `validateAuthentifiers` on every unit spent from such an address, the crash is deterministic and universal: every node that receives/validates the malicious spending unit crashes. This halts the network the same way the Tally VM panic halts SEDA validators — nodes stop being able to reach consensus/confirm new units until manually patched and restarted, which is a network-wide denial of service reachable from a single crafted, unprivileged unit.

### Likelihood Explanation
High likelihood: the attacker needs no special privileges — only the ability to post two ordinary units (a `definition_template` message and a unit establishing/using an address whose definition references that template with incomplete `params`), both of which are standard, unprivileged unit types available to any user. No race condition or timing dependency is required; the crash triggers deterministically on the first attempt by any node to validate the crafted spending unit.

### Recommendation
Wrap the `replaceInTemplate()` call (and the `rows.length !== 1` check) inside `validateAuthentifiers()`'s `'definition template'` case in a `try/catch`, mirroring the handling already present in `validateDefinition()`, and convert any `NoVarException`/other exception into a normal `cb2(false)` (authentifier evaluation failure) instead of letting it propagate uncaught. Additionally, consider replacing the many `throw Error(...)` calls used as "should never happen" assertions throughout consensus-critical validation code with recoverable error callbacks, so a single malformed/adversarial input cannot escalate into a process-wide crash.

### Proof of Concept
1. Post unit A: `{ app: 'definition_template', payload: ["hash", {"algo": "sha256", "hash": "$missing_var"}] }` (any template referencing a variable, e.g. `$missing_var`).
2. Create/define an address B whose definition is `['definition template', [unitA, {}]]` — note `params` is empty, so `$missing_var` is never supplied.
3. Post any unit spending from address B, signed by its owner as normal.
4. When any node validates this unit, `validateAuthor` → `validateAuthentifiers` → the `'definition template'` case runs `replaceInTemplate(arrTemplate, {})`, which throws `NoVarException` for the missing `$missing_var` placeholder, uncaught, at `definition.js:1480` inside the call path at `definition.js:802-819`, crashing the node via `network.js:4530-4543`.

### Citations

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

**File:** definition.js (L328-339)
```javascript
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
```

**File:** definition.js (L646-820)
```javascript
function validateAuthentifiers(conn, address, this_asset, arrDefinition, objUnit, objValidationState, assocAuthentifiers, cb){
	
	function evaluate(arr, path, cb2){
		var op = arr[0];
		var args = arr[1];
		switch(op){
			case 'or':
				// ['or', [list of options]]
				var res = false;
				var index = -1;
				async.eachSeries(
					args,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							res = res || arg_res;
							cb3(); // check all members, even if required minimum already found
							//res ? cb3("found") : cb3();
						});
					},
					function(){
						cb2(res);
					}
				);
				break;
				
			case 'and':
				// ['and', [list of requirements]]
				var res = true;
				var index = -1;
				async.eachSeries(
					args,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							res = res && arg_res;
							cb3(); // check all members, even if required minimum already found
							//res ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(res);
					}
				);
				break;
				
			case 'r of set':
				// ['r of set', {required: 2, set: [list of options]}]
				var count = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb3){
						index++;
						evaluate(arg, path+'.'+index, function(arg_res){
							if (arg_res)
								count++;
							cb3(); // check all members, even if required minimum already found, so that we don't allow invalid sig on unchecked path
							//(count < args.required) ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(count >= args.required);
					}
				);
				break;
				
			case 'weighted and':
				// ['weighted and', {required: 15, set: [{value: boolean_expr, weight: 10}, {value: boolean_expr, weight: 20}]}]
				var weight = 0;
				var index = -1;
				async.eachSeries(
					args.set,
					function(arg, cb3){
						index++;
						evaluate(arg.value, path+'.'+index, function(arg_res){
							if (arg_res)
								weight += arg.weight;
							cb3(); // check all members, even if required minimum already found
							//(weight < args.required) ? cb3() : cb3("found");
						});
					},
					function(){
						cb2(weight >= args.required);
					}
				);
				break;
				
			case 'sig':
				// ['sig', {algo: 'secp256k1', pubkey: 'base64'}]
				//console.log(op, path);
				var signature = assocAuthentifiers[path];
				if (!signature)
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'secp256k1';
				if (algo === 'secp256k1'){
					if (objValidationState.bUnsigned && signature[0] === "-") // placeholder signature
						return cb2(true);
					var res = ecdsaSig.verify(objValidationState.unit_hash_to_sign, signature, args.pubkey);
					if (!res)
						fatal_error = "bad signature at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported sig algo at path "+path;
					return cb2(false);
				}
				break;
				
			case 'hash':
				// ['hash', {algo: 'sha256', hash: 'base64'}]
				if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'sha256';
				if (algo === 'sha256'){
					var res = (args.hash === crypto.createHash("sha256").update(assocAuthentifiers[path], "utf8").digest("base64"));
					if (!res)
						fatal_error = "bad hash at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported hash algo at path "+path;
					return cb2(false);
				}
				break;
				
			case 'address':
				// ['address', 'BASE32']
				if (!pathIncludesOneOfAuthentifiers(path, arrAuthentifierPaths, bAssetCondition))
					return cb2(false);
				var other_address = args;
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						evaluate(arrInnerAddressDefinition, path, cb2);
					},
					ifDefinitionNotFound: function(definition_chash){
						try {
							var arrDefiningAuthors = objUnit.authors.filter(function(author){
								return (author.address === other_address && author.definition && objectHash.getChash160(author.definition) === definition_chash);
							});
						}
						catch (e) {
							return cb2(false);
						}
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
						var arrInnerAddressDefinition = arrDefiningAuthors[0].definition;
						evaluate(arrInnerAddressDefinition, path, cb2);
					}
				});
				break;
				
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

**File:** validation.js (L1149-1212)
```javascript
function validateAuthor(conn, objAuthor, objUnit, objValidationState, callback){
	if (objValidationState.bAA && hasFieldsExcept(objAuthor, ["address"]))
		throw Error("unknown fields in AA author");
	if (!objValidationState.bAA) {
		if (hasFieldsExcept(objAuthor, ["address", "authentifiers", "definition"]))
			return callback("unknown fields in author");
		if (!isNonemptyObject(objAuthor.authentifiers) && !objUnit.content_hash)
			return callback("no authentifiers");
		for (var path in objAuthor.authentifiers) {
			if (!isNonemptyString(objAuthor.authentifiers[path]))
				return callback("authentifiers must be nonempty strings");
			if (objAuthor.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return callback("authentifier too long");
		}
	}
	
	var bNonserial = false;
	var bInitialDefinition = false;

	if (objValidationState.bAA) {
		storage.readAADefinition(conn, objAuthor.address, objValidationState.aa_mci, function (arrDefinition) {
			if (!arrDefinition)
				throw Error("AA definition not found " + objAuthor.address);
			checkSerialAddressUse();
		});
		return;
	}
	
	var arrAddressDefinition = objAuthor.definition;
	if (isNonemptyArray(arrAddressDefinition)){
		if (arrAddressDefinition[0] === 'autonomous agent')
			return callback('AA cannot be defined in authors');
		// todo: check that the address is really new?
		validateAuthentifiers(arrAddressDefinition);
	}
	else if (!("definition" in objAuthor)){
		if (objUnit.content_hash){ // nothing else to check
			objValidationState.sequence = 'final-bad';
			return callback();
		}
		// we check signatures using the latest address definition before last ball
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){
				storage.readAADefinition(conn, objAuthor.address, objValidationState.last_ball_mci, function (arrAADefinition) {
					if (arrAADefinition)
						return callback(createTransientError("will not validate unit signed by AA"));
					if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci)
						return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " not found before last ball");
					findUnstableInitialDefinition(definition_chash, function (arrDefinition) {
						if (!arrDefinition)
							return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " is not defined");
						bInitialDefinition = true;
						validateAuthentifiers(arrDefinition);
					});
				});
			},
			ifFound: function(arrAddressDefinition){
				validateAuthentifiers(arrAddressDefinition);
			}
		});
	}
	else
		return callback("bad type of definition");
	
```
