### Title
Unhandled synchronous `throw` in `definition template` evaluation crashes full nodes validating a crafted unit - ([File: definition.js])

### Summary
The `definition template` operator inside `validateAuthentifiers`/`evaluate` in `definition.js` throws a synchronous `Error` from inside a `conn.query` callback whenever the referenced `definition_template` lookup does not return exactly one row. Because this throw happens inside an asynchronous database callback, it is not caught by any surrounding `try/catch` and propagates as a Node.js `uncaughtException`. `network.js` installs a global `uncaughtException` handler that deliberately re-throws to crash the process (`throw err; // crash the process to avoid ending up in an inconsistent state`). An attacker who defines an address (or asset condition) using a `['definition template', ...]` clause that references a unit containing two `definition_template` messages can force `rows.length !== 1` deterministically, causing every full node that evaluates that address definition (e.g., when validating a unit that spends from, or is authored by, that address) to crash.

### Finding Description
`definition.js` implements the `'definition template'` operator as follows: [1](#0-0) 

The handler queries for a stable `definition_template` message matching the referenced `unit`, and unconditionally throws if the row count is not exactly 1:
```
if (rows.length !== 1)
    throw Error("not 1 template");
```
Normally a `unit` primary key would yield at most one row, but the join is against the `messages` table (`messages JOIN units USING(unit)`), so if the referenced unit contains **two or more** messages with `app='definition_template'`, the join returns multiple rows for the same `unit`, guaranteeing `rows.length !== 1` and triggering the throw. This throw occurs inside the `conn.query` callback, a context which is not wrapped by any `try/catch` in the calling chain (`evaluate` → `validateAuthentifiers` → `validateDefinition`), so it becomes an uncaught exception.

`network.js` explicitly re-throws in its uncaught exception handler to intentionally crash the whole node process: [2](#0-1) 

An unprivileged unit poster can:
1. Post a unit containing two `app='definition_template'` messages (a normal, valid unit type), and let it become stable.
2. Define (or have an existing) address whose definition includes `['definition template', [that_unit, params]]`.
3. Post (or wait for someone else to post) any unit that requires evaluating that address's definition — e.g. spending from the address, using it as an author, or referencing it via the `'address'` operator in another definition — which invokes `validateAuthentifiers` → `evaluate` → the `'definition template'` branch.

Every full node that processes/validates that triggering unit will hit the `throw Error("not 1 template")` inside the DB callback and crash.

### Impact Explanation
This is analogous to CVE-2024-44775 (unhandled null/invalid-state exception in message processing crashing the broker): a single crafted, otherwise-valid on-chain object (a unit defining/using an address with a `definition template` clause pointing at a multiply-defined template) causes an unhandled exception that kills the Node.js process on every full node that validates it. Since crash-on-validation is deterministic and unavoidable (the same code path runs on every node relaying/validating the unit), this can be used to repeatedly crash full nodes across the network whenever they attempt to confirm the malicious unit, preventing the network from confirming new units through the affected path — a network-availability impact, not merely a single-peer disconnect.

### Likelihood Explanation
Likelihood is high: constructing a unit with two `definition_template` messages, and an address definition using `['definition template', ...]`, are ordinary, permitted primitives available to any unprivileged unit poster / address definer; no privileged role or malicious peer/hub behavior is required, and the vulnerable code path is reached purely through legitimate unit and definition validation logic.

### Recommendation
In `definition.js`, replace the `throw Error("not 1 template")` with a call to `cb2(false)` and set `fatal_error` (consistent with how other authentifier-evaluation errors are handled, e.g. in the `'sig'`/`'hash'` cases), so that ambiguous or missing template lookups fail validation gracefully instead of raising an unhandled exception. Additionally, audit other `conn.query` callbacks in `definition.js`/`validation.js` for bare `throw` statements that are not wrapped by try/catch, since they present the same uncaught-exception crash risk.

### Proof of Concept
1. Attacker posts unit `U1` with two messages: `{app: 'definition_template', payload: <template A>}` and `{app: 'definition_template', payload: <template B>}`, and gets it stable and `sequence='good'`.
2. Attacker defines (or someone controls) address `ADDR` whose definition is `['definition template', ['U1', {...}]]`.
3. Attacker (or anyone) posts a unit spending from `ADDR` (or otherwise causing `ADDR`'s definition to be evaluated, e.g. via the `'address'` operator referencing `ADDR`).
4. Every node validating that spending unit executes `evaluate` on the `'definition template'` branch in [3](#0-2) , the `conn.query` callback finds `rows.length === 2`, and throws `Error("not 1 template")`, which is uncaught and crashes the node per the handler in [2](#0-1) .

### Citations

**File:** definition.js (L802-818)
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
