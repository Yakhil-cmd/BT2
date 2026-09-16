### Title
Unhandled crash via `throw Error("not 1 template")` in address authentifier evaluation - (File: definition.js)

### Summary
`Definition.validateAuthentifiers()` in `definition.js` evaluates an address's spending-condition tree against the authentifiers of every unit signed by that address. When the tree contains a `'definition template'` operator, the referenced template row is looked up per-unit with an `objValidationState.last_ball_mci`-bound query, and if the row count is not exactly 1, the code throws an uncaught `Error` instead of returning a validation failure through the callback, unlike its sibling implementation in `validateDefinition()` which handles the same condition gracefully.

### Finding Description
Any address can define itself with an authentifier tree containing `['definition template', [unit, params]]`, referencing an existing `definition_template` unit. This is accepted by `validateDefinition()` at the time the definition is introduced (via `author.definition` or `address_definition_change`), because that function's own copy of the `'definition template'` handling returns a graceful error when the lookup fails: [1](#0-0) 

However, every subsequent unit signed by that address goes through `validateAuthentifiers()` (called from `validation.js`'s `validateAuthor`) to check the actual signature, and its own independent implementation of the same `'definition template'` op throws instead of failing gracefully: [2](#0-1) 

The query restricts matching rows to `main_chain_index<=objValidationState.last_ball_mci`, where `last_ball_mci` is derived from the *signing unit's own* `last_ball_unit`/`last_ball`, which the author fully controls: [3](#0-2) 

Because the author can freely pick an older, still-valid `last_ball_unit` for a later unit (the DAG's `last ball mci must not retreat` rule only bounds it from below via parents, not from above), they can construct a unit whose `last_ball_mci` predates the main-chain stabilization of the referenced `definition_template` unit. The query then returns 0 rows, and `rows.length !== 1` triggers `throw Error("not 1 template")` inside an asynchronous `conn.query` callback, which is not wrapped in any try/catch up the call chain (`validateAuthentifiers` → `validateAuthor` → `validate` in `validation.js`).

An uncaught exception thrown inside an async callback in Node.js propagates to `process.on('uncaughtException')`, which explicitly re-throws to crash the process: [4](#0-3) 

This mirrors the reported CVE's bug class: a missing null/branch check on an externally influenced lookup result leads directly to a crash, and here the crash is triggered purely by validating a routine unit — reachable by any unprivileged unit poster who controls their own address definition.

### Impact Explanation
Any full node or hub that receives and validates the crafted unit executes `Definition.validateAuthentifiers()` and crashes with an uncaught exception, terminating the node process. Since this occurs during ordinary unit validation (not a privileged or peer-trust-dependent code path), a single malicious unit can be propagated to crash every node that processes it, disrupting the network's ability to validate and confirm new units — satisfying the "network unable to confirm new units" impact class.

### Likelihood Explanation
Likelihood is significant: any user can create an address whose definition includes a `'definition template'` reference, get that definition accepted (since `validateDefinition` tolerates the same edge case gracefully at registration time), and later post a unit signed by that address while deliberately choosing an older `last_ball_unit` so that the template lookup misses. No special privileges, witness cooperation, or timing races with other users are required — the attacker fully controls both the referenced template unit and the `last_ball_unit` of the signing unit.

### Recommendation
In `definition.js`'s `validateAuthentifiers()` `'definition template'` case, replace `throw Error("not 1 template")` with a graceful failure path consistent with `validateDefinition()`, e.g. `fatal_error = "template not found or too many"; return cb2(false);` (or equivalent non-throwing rejection), ensuring a missing/duplicate template row invalidates just this authentifier branch instead of crashing the process.

### Proof of Concept
1. Post a `definition_template` unit `T` with some template payload.
2. Create address `A` whose definition is `['definition template', [T, {...}]]` wrapped so it forms a valid signature branch (e.g., `['and', [['definition template', [T, {p:'v'}]], ['sig', {...}]]]`), and register it via `author.definition` in an initial unit `U1`; `validateDefinition` accepts it since `T` is already stable relative to `U1.last_ball_mci`.
3. Wait for a subsequent unit `U2` to be built where `T`'s stabilization mci has advanced past some earlier still-valid last ball point.
4. From address `A`, post unit `U2` signed with the same definition but explicitly set `last_ball_unit`/`last_ball` to an earlier stable point whose mci is `< T`'s `main_chain_index`, while still satisfying the "last ball mci must not retreat" parent constraint.
5. When any node validates `U2`, `validateAuthentifiers()`'s `'definition template'` query returns 0 rows, hits `throw Error("not 1 template")`, and crashes the node process via the global `uncaughtException` handler.

### Citations

**File:** definition.js (L321-342)
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
				);
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

**File:** validation.js (L1243-1254)
```javascript
	function validateAuthentifiers(arrAddressDefinition){
		Definition.validateAuthentifiers(
			conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers, 
			function(err, res){
				if (err) // error in address definition
					return callback(err);
				if (!res) // wrong signature or the like
					return callback("authentifier verification failed");
				checkSerialAddressUse();
			}
		);
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
