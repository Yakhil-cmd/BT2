### Title
Unhandled `throw Error` in `definition template` authentifier evaluation crashes the node process - (File: definition.js)

### Summary
The MariaDB CVE describes a DoS where malformed input passed to `Field::set_default` is not defensively validated and causes an uncaught crash. The closest reachable analog in ocore is the `'definition template'` operator inside `evaluate()` used by `validateAuthentifiers`, which uses `throw Error(...)` instead of returning an error through the callback chain when the referenced template unit is not found or ambiguous, unlike the parallel, safe implementation used by `validateDefinition`.

### Finding Description
Address definitions support the `['definition template', [unit, params]]` operator, which looks up a `definition_template` message previously posted to the DAG and substitutes `params` into it via `replaceInTemplate` [1](#0-0) .

There are two independent implementations of this operator:
1. In `validateDefinition`'s `evaluate()`, the row-count check is defensive and reports errors through the callback: `if (rows.length !== 1) return cb("template not found or too many");`, and exceptions from `replaceInTemplate` are caught with `try/catch` [2](#0-1) .
2. In `validateAuthentifiers`'s `evaluate()` (used when actually checking signatures at spend time), the same lookup instead does `if (rows.length !== 1) throw Error("not 1 template");` and calls `replaceInTemplate` with **no** surrounding `try/catch` [3](#0-2) .

`validateAuthentifiers` is invoked from `validation.js` during author/authentifier validation of every posted unit, inside an `async.series` pipeline that itself runs inside `mutex.lock(...)` with no synchronous `try/catch` wrapping these downstream async callbacks (only the initial `objectHash.getUnitHash` call is guarded) [4](#0-3) [5](#0-4) . If a `throw` occurs asynchronously inside a `conn.query` callback deep in this chain, it is not caught by any `try/catch` and propagates to Node's event loop, triggering the global handler in `network.js`, which deliberately re-throws to **crash the entire process**: `throw err; // crash the process to avoid ending up in an inconsistent state` [6](#0-5) .

Because the "safe" cb-based check and the "unsafe" throwing check are two separately maintained code paths querying the same table under possibly different `last_ball_mci`/timing/state assumptions (e.g. asset-condition evaluation via `bAssetCondition`, or definitions re-validated on every spend as noted in the comment "we need to re-validate the definition every time... because... redefinition... complexity might change") [7](#0-6) , any divergence between the two checks (template unit becomes unavailable/duplicated/differently-sequenced between the two evaluations, or reachable via `bAssetCondition` paths that don't necessarily re-run the safe `validateDefinition` check first) results in the unsafe `throw` firing.

### Impact Explanation
An uncaught `throw` in unit/authentifier validation crashes the entire ocore process for every full node processing the maliciously crafted unit (the handler explicitly re-throws to force a crash). This is a network-wide denial of service: a node crash halts confirmation of new units for that node, and since the code is common to all full nodes, a single crafted unit referencing a `definition template` in an address definition (posted by any unprivileged unit author) can potentially crash every node that processes/relays it, matching the "network unable to confirm new units" bar for a valid analog.

### Likelihood Explanation
Reaching this code path only requires an ordinary user to author a unit spending from (or using in an asset condition) an address whose definition contains `['definition template', [unit, params]]`, referencing a `definition_template` unit under specific state conditions where the "safe" validateDefinition check and the "unsafe" validateAuthentifiers check can disagree about the row count (e.g. via asset-condition evaluation paths, redefinition-triggered re-validation, or template units that transition between good/non-good sequence between checks). The exact triggering race/state divergence could not be fully confirmed with the tools available in this session (see caveat below), so likelihood is assessed as plausible but not fully proven.

### Recommendation
Replace the unguarded `throw Error("not 1 template")` and the un-try/caught call to `replaceInTemplate` in the `validateAuthentifiers` evaluate() branch (`definition.js`, the `'definition template'` case around line 802-819) with the same defensive pattern used in `validateDefinition`: return the error via `cb2(false)`/an explicit error callback instead of throwing, and wrap `replaceInTemplate` in `try/catch`, treating `NoVarException` and any other failure as authentifier-evaluation failure rather than a fatal exception.

### Proof of Concept
Not independently reproduced end-to-end; this report is based on static code-path analysis identifying the divergence between the safe (`validateDefinition`) and unsafe (`validateAuthentifiers`) implementations of the `'definition template'` operator and the global crash-on-uncaught-exception handler in `network.js`. Full confirmation of a concrete state (e.g., under which exact conditions `rows.length !== 1` at authentifier-check time while `validateDefinition` previously passed) would require dynamic testing/tracing that was not available in this session — this is explicitly noted as unverified.

### Citations

**File:** definition.js (L321-339)
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

**File:** definition.js (L1449-1454)
```javascript
	// we need to re-validate the definition every time, not just the first time we see it, because:
	// 1. in case a referenced address was redefined, complexity might change and exceed the limit
	// 2. redefinition of a referenced address might introduce loops that will drive complexity to infinity
	// 3. if an inner address was redefined by keychange but the definition for the new keyset not supplied before last ball, the address
	// becomes temporarily unusable
	validateDefinition(conn, arrDefinition, objUnit, objValidationState, arrAuthentifierPaths, bAssetCondition, function(err){
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

**File:** validation.js (L131-138)
```javascript
	try{
		// UnitError is linked to objUnit.unit, so we need to ensure objUnit.unit is true before we throw any UnitErrors
		if (objectHash.getUnitHash(objUnit) !== objUnit.unit)
			return callbacks.ifJointError("wrong unit hash: "+objectHash.getUnitHash(objUnit)+" != "+objUnit.unit);
	}
	catch(e){
		return callbacks.ifJointError("failed to calc unit hash: "+e);
	}
```

**File:** validation.js (L357-443)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
		
		var conn = null;
		var commit_fn = null;
		var start_time = null;

		async.series(
			[
				function(cb){
					if (external_conn) {
						conn = external_conn;
						start_time = Date.now();
						commit_fn = function (cb2) { cb2(); };
						return cb();
					}
					db.takeConnectionFromPool(function(new_conn){
						conn = new_conn;
						start_time = Date.now();
						commit_fn = function (cb2) {
							conn.query(objValidationState.bAdvancedLastStableMci ? "COMMIT" : "ROLLBACK", function () { cb2(); });
						};
						conn.query("BEGIN", function(){cb();});
					});
				},
				function(cb){
					profiler.start();
					checkDuplicate(conn, objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-checkDuplicate');
					profiler.start();
					objUnit.content_hash ? cb() : validateHeadersCommissionRecipients(objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-hc-recipients');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateHashTreeBall(conn, objJoint, cb);
				},
				function(cb){
					profiler.stop('validation-hash-tree-ball');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateParentsExistAndOrdered(conn, objUnit, cb);
				},
				function(cb){
					profiler.stop('validation-parents-exist');
					profiler.start();
					!objUnit.parent_units
						? cb()
						: validateHashTreeParentsAndSkiplist(conn, objJoint, cb);
				},
				function(cb){
					profiler.stop('validation-hash-tree-parents');
				//	profiler.start(); // conflicting with profiling in determineIfStableInLaterUnitsAndUpdateStableMcFlag
					!objUnit.parent_units
						? cb()
						: validateParents(conn, objJoint, objValidationState, cb);
				},
				function(cb){
				//	profiler.stop('validation-parents');
					profiler.start();
					!objJoint.skiplist_units
						? cb()
						: validateSkiplist(conn, objJoint.skiplist_units, cb);
				},
				function(cb){
					profiler.stop('validation-skiplist');
					validateWitnesses(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateAATrigger(conn, objUnit, objValidationState, cb);
				},
				function (cb) {
					validateTpsFee(conn, objJoint, objValidationState, cb);
				},
				function(cb){
					profiler.start();
					validateAuthors(conn, objUnit.authors, objUnit, objValidationState, cb);
				},
				function(cb){
					profiler.stop('validation-authors');
					profiler.start();
					objUnit.content_hash ? cb() : validateMessages(conn, objUnit.messages, objUnit, objValidationState, cb);
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
