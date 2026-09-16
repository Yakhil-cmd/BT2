## Analysis Result

The mah-jong CVE-2004-0458 bug class — a missing argument that triggers a null-pointer dereference and crashes the server — has a concrete analog in ocore's crash-on-uncaught-exception design combined with insufficiently defensive property access in unit/AA validation paths reachable from a single posted unit.

### Title
Remote unit-triggered uncaught exception crashes the full node process - (File: network.js)

### Summary
ocore's global `uncaughtException` handler deliberately rethrows any uncaught error to crash the process [1](#0-0) . Because unit/AA validation runs many nested, asynchronous code paths that use `throw Error(...)` for conditions the authors believed to be "impossible" invariants (e.g., missing definitions, missing template rows, more-than-one matching row, cache-miss assumptions) rather than routing them through `callbacks.ifUnitError`, a specially crafted unit, AA trigger, or definition-template payload from an unprivileged unit poster can hit one of these `throw` statements. Because the validate pipeline executes inside `mutex.lock` and various nested `async` callbacks (not inside a try/catch that funnels to a callback), the thrown error surfaces as an uncaught exception in `network.js`, which is configured to crash the entire node — a remote, unauthenticated, single-unit denial of service, directly analogous to a "missing argument causes crash" bug class.

### Finding Description
Multiple validation and AA-composition code paths use hard `throw Error(...)` for conditions that can be influenced or reached via attacker-controlled data instead of returning a validation error via callback:
- `validateAuthor`/`readAADefinition` throws if an AA definition is not found for a serial address expected to be an AA [2](#0-1) .
- `definition.js`'s `definition template` evaluation throws `"not 1 template"` if the referenced template unit's row count in the query differs from 1, and parses/executes attacker-supplied `params` against it [3](#0-2) .
- `evaluate()` inner logic throws `"more than 1 address definition"` when multiple co-authors claim to define the same address [4](#0-3)  and again in the authentifier evaluator [5](#0-4) .
- `aa_composer.js`'s `getTrigger()` throws `"no outputs to " + receiving_address"` if a data-only trigger unit with no matching payment output somehow reaches it, and `handlePrimaryAATrigger` throws if `storage.assocStableUnits[unit]` cache lookup unexpectedly misses [6](#0-5) [7](#0-6) .
- The `validateAndSaveUnit` callback for AA response units throws on any joint/transient error or unexpected dependency instead of handling it gracefully, since it assumes AA-generated units can never be invalid [8](#0-7) .

None of these `throw` statements are wrapped by validation's outer error-handling machinery (which only expects string/object errors passed to `callback`/`callbacks.ifUnitError`), so any of them escaping to the top level triggers Node's `uncaughtException` handler, which explicitly re-throws to crash the process [1](#0-0) .

### Impact Explanation
Reaching any of these code paths remotely (e.g., through a maliciously crafted unit posted by any peer/wallet, or through a crafted AA definition/trigger designed to create a race between cache state and DB state) crashes the full ocore node process, taking it offline. This is a network-wide denial-of-service risk: a single specially crafted unit or AA definition can be broadcast to bring down any node (light or full) that processes it, matching the "server crash via null pointer dereference on missing argument" bug class in the CVE, generalized to "server crash via unhandled invariant-violation throw."

### Likelihood Explanation
Likelihood is Medium: most of these `throw` conditions require somewhat unusual or racy states (e.g., a cache miss for a supposedly-stable unit, a template lookup returning zero or multiple rows, concurrent redefinition of a co-author's address) rather than a single trivially malformed field. However, several are directly reachable by choosing unit content: e.g. supplying a `definition template` op referencing a unit ID with zero matching template rows (deleted/nonexistent unit), or supplying multiple co-author definitions for the same inner address in an `and`/`or` address-definition tree, both of which an attacker fully controls when constructing a unit.

### Recommendation
- Replace `throw Error(...)` in validation and AA-composition code paths that depend on remotely-supplied data (`definition.js` template lookups and duplicate-definition checks, `aa_composer.js` `getTrigger`/cache lookups, `validateAuthor`'s AA-definition lookup) with proper error propagation via the existing callback error channels (`cb("...")` / `callbacks.ifUnitError(...)`), so malformed input results in unit rejection rather than a process crash.
- Wrap the top-level `validate()` state machine and AA trigger execution paths in a try/catch that converts unexpected thrown errors into `ifUnitError`/`ifTransientError` calls instead of letting them propagate to `uncaughtException`.
- Add fuzz/negative test coverage specifically targeting the `definition template`, nested `address`, and AA trigger paths with malformed/edge-case units to catch newly introduced unguarded throws before they reach production.

### Proof of Concept
Conceptual PoC (cannot be executed without live node access):
1. Construct a valid address definition using `['definition template', [unitId, params]]` where `unitId` references a unit that either does not exist or was never sent as a `definition_template` message (violating the assumed single-row invariant).
2. Post/sign a unit spending from an address using this definition (or use it as an asset condition where reachable).
3. On validation, `conn.query(...)` for the template returns 0 rows, hitting `if (rows.length !== 1) throw Error("not 1 template");` at [9](#0-8) , an uncaught throw inside the async DB callback chain that is not routed through the validation callback mechanism.
4. This propagates to the global `uncaughtException` handler in `network.js`, which rethrows and crashes the receiving node's process [1](#0-0) .

Note: full confirmation that this exact throw is unreachable from earlier `hasOwnProperty`/validation guards would require deeper tracing of `validateDefinition`'s `definition template` handling (not fully covered in the indexed snippets), so likelihood/reachability here should be treated as an analog hypothesis for a background Devin session to confirm against the live `definition.js` `case 'definition template':` validation branch in `validateDefinition()` before treating it as confirmed exploitable.

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

**File:** validation.js (L1168-1174)
```javascript
	if (objValidationState.bAA) {
		storage.readAADefinition(conn, objAuthor.address, objValidationState.aa_mci, function (arrDefinition) {
			if (!arrDefinition)
				throw Error("AA definition not found " + objAuthor.address);
			checkSerialAddressUse();
		});
		return;
```

**File:** definition.js (L296-299)
```javascript
						if (arrDefiningAuthors.length === 0) // no address definition in the current unit
							return bAllowUnresolvedInnerDefinitions ? cb(null, true) : cb("definition of inner address "+other_address+" not found");
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
```

**File:** definition.js (L792-795)
```javascript
						if (arrDefiningAuthors.length === 0) // no definition in the current unit
							return cb2(false);
						if (arrDefiningAuthors.length > 1)
							throw Error("more than 1 address definition");
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

**File:** aa_composer.js (L104-106)
```javascript
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
```

**File:** aa_composer.js (L394-397)
```javascript
	if (Object.keys(trigger.outputs).length === 0)
		throw Error("no outputs to " + receiving_address);
	return trigger;
}
```

**File:** aa_composer.js (L1800-1837)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
			ifOk: function (objAAValidationState, validation_unlock) {
				if (objAAValidationState.sequence !== 'good')
					throw Error("nonserial AA");
				validation_unlock();
				objAAValidationState.bUnderWriteLock = true;
				objAAValidationState.conn = conn;
				objAAValidationState.batch = batch;
				objAAValidationState.initial_trigger_mci = mci;
				objAAValidationState.bDryRun = trigger_opts.bDryRun;
				writer.saveJoint(objJoint, objAAValidationState, null, function(err){
					if (err)
						throw Error('AA writer returned error: ' + err);
					cb();
				});
			}
		}, conn);
```
