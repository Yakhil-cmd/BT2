## Analysis Result

### Title
Null-pointer-style crash via missing `attestors`/`address` params in `attestation[]` formula evaluation - (File: formula/evaluation.js)

### Summary
CVE-2021-44923 is a NULL pointer dereference in gpac's `gf_dump_vrml_dyn_field`, triggered when a "dump"/serialization routine assumes a field structure exists but the parsed input omits it, causing a crash. The `ocore` analog is in the oscript `attestation[...]` formula operator: the static validator (`formula/validation.js`) never enforces that the `attestors` and `address` named parameters are actually present, while the runtime evaluator (`formula/evaluation.js`) unconditionally dereferences `.value` on those same parameters, assuming they exist.

### Finding Description
`getAttestationError()` in `formula/validation.js` only validates the parameters that are *present* in the `attestation[...]` params object — it iterates `for (var name in params)` and checks each supplied name against an allow-list (`attestors, address, ifseveral, ifnone, type`), rejecting unknown fields or bad values: [1](#0-0) 

Nothing in this function (nor in the AA static-definition validator `aa_validation.js` that calls into `validateFormula`) enforces that `attestors` or `address` must be among the supplied keys — a formula like `attestation[ifnone=5]` (only supplying the optional `ifnone` param) passes this check because there are no "unknown fields" and no invalid values to reject.

At runtime, `formula/evaluation.js`'s `evaluate()` handles the `attestation` op by unconditionally accessing `.value` on `params.attestors` and `params.address` with no existence guard, unlike the sibling `asset`/`amount` handling in the very same block which is defensively guarded with `if (evaluated_params.asset){...}`: [2](#0-1) [3](#0-2) 

If `attestors` (or `address`) is absent, `params.attestors` (or `params.address`) is `undefined`, and `params.attestors.value` throws a `TypeError: Cannot read properties of undefined (reading 'value')` — the direct JS analogue of a null-pointer dereference during "evaluation/serialization" of attacker-controlled structured data.

### Impact Explanation
Formula evaluation of this kind runs during AA trigger processing (`aa_composer.js` → `formulaParser.evaluate`) and during on-chain address/asset-definition evaluation of `formula` conditions (`definition.js`, case `'formula'`). Both paths are reachable by an unprivileged unit poster: any user can define an AA (or an address/asset spending condition) containing such a malformed `attestation[]` formula, then trigger it (or attempt to spend from it) with an ordinary unit. The thrown `TypeError` occurs deep inside nested `async`/DB-callback chains that are not wrapped in `try/catch` for JS runtime errors (only explicit validation errors are propagated via `cb(err)`). An uncaught exception of this kind is caught only by the top-level `process.on('uncaughtException', ...)` handler, which deliberately re-throws to crash the process: [4](#0-3) 

Because every full/witness node that processes the triggering unit (or evaluates the tainted spending condition) executes the same evaluator code path, a single crafted unit can crash all validating full nodes that reach this code, preventing the network from confirming new units — a network-wide availability impact rather than a single-peer crash.

### Likelihood Explanation
Medium-to-High: constructing the malformed formula requires only knowledge of the oscript syntax for named-parameter operators (no privileged access, no race condition, no malicious peer/hub needed). The only residual uncertainty is whether the `oscript` grammar rule for `attestation[...]` syntactically permits omitting `attestors`/`address` while supplying only other optional named params (e.g., `ifnone`); I was not able to fully inspect the neace-generated grammar rule for `attestation` in `formula/grammars/oscript.js` within the available search budget to confirm this at the parser level, so this should be verified directly against the grammar before treating this as fully proven.

### Recommendation
- In `getAttestationError()` (`formula/validation.js`), explicitly require that `attestors` and `address` are present in `params` (mirroring how `getInputOrOutputError()` already requires `if (!Object.keys(params).length) return 'no params';`, but going further to require the specific mandatory keys).
- In `formula/evaluation.js`'s `attestation` case, add existence guards (`if (!params.attestors) return setFatalError(...)`, similarly for `params.address`) before dereferencing `.value`, consistent with the defensive style already used for `asset`/`amount` in the same function.
- Audit other formula operators for the same "validator checks only present keys, evaluator assumes required keys always present" mismatch pattern.

### Proof of Concept
1. Author an AA (or an address/asset spending condition using the `formula` operator) whose getters/state/message payload contains the oscript expression:
   `attestation[ifnone=false]`
   (omitting the `attestors` and `address` named parameters).
2. This definition passes `aa_validation.js` / `formula/validation.js` static validation because `getAttestationError` finds no unknown fields and no invalid values among the parameters that are actually supplied.
3. Post the AA definition, then send a trigger unit to it (or attempt a spend governed by the tainted condition).
4. During evaluation, `formula/evaluation.js` executes `params.attestors.value` with `params.attestors === undefined`, throwing an uncaught `TypeError`, which propagates past all async error-first callbacks and is caught only by the global `uncaughtException` handler in `network.js`, which re-throws and crashes the node process — repeatable against every full node that processes the unit.

### Citations

**File:** formula/validation.js (L142-154)
```javascript
		if (operator !== '=')
			return 'not =';
		if (['attestors', 'address', 'ifseveral', 'ifnone', 'type'].indexOf(name) === -1)
			return 'unknown field: ' + name;
		if (typeof value !== 'string') // expression
			continue;
		switch (name) {
			case 'attestors':
				value = value.trim();
				if (!value)
					return 'empty attestors';
				var attestor_addresses = value.split(':');
				if (!attestor_addresses.every(ValidationUtils.isValidAddress)) return 'bad attestor address: ' + value;
```

**File:** formula/evaluation.js (L847-856)
```javascript
						if (evaluated_params.asset){
							var v = evaluated_params.asset.value;
							if (!ValidationUtils.isValidBase64(v, constants.HASH_LENGTH) && v !== 'base')
								return setFatalError('bad asset', { arr }, false, cb);
						}
						if (evaluated_params.amount){
							var v = evaluated_params.amount.value;
							if(!isFiniteDecimal(v))
								return setFatalError('bad amount', { arr }, false, cb);
						}
```

**File:** formula/evaluation.js (L906-914)
```javascript
						if (typeof params.attestors.value !== 'string')
							return setFatalError('attestors is not a string', { arr }, false, cb);
						var arrAttestorAddresses = params.attestors.value.split(':');
						if (!arrAttestorAddresses.every(ValidationUtils.isValidAddress)) // even if some addresses are ok
							return setFatalError('bad attestors', { arr }, false, cb);

						var v = params.address.value;
						if (!ValidationUtils.isValidAddress(v))
							return setFatalError('bad address in attestation: ' + v, { arr }, false, cb);
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
