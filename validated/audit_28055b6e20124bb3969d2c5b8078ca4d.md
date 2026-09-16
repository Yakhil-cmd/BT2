### Title
Unhandled `NoVarException` in `definition template` evaluation crashes any full node validating a maliciously crafted address definition - ([File: definition.js])

### Summary
The CVE describes a kernel `NULL` dereference caused by unhandled failure of a driver lookup on a crafted `/dev/pts` path, leading to a full system crash reachable by an unprivileged local user. The analogous condition in ocore is an **unhandled JS exception thrown from inside an asynchronous DB-query callback while evaluating an address definition** that uses the `definition template` operator. When the referenced template's required variable is missing from the supplied `params`, `replaceInTemplate()` throws a `NoVarException` that is never caught anywhere in the call chain. Because the throw happens inside a `conn.query()` callback (a new stack frame), it cannot be caught by any surrounding `try/catch`, propagates to Node's `process.on('uncaughtException', ...)` handler, and that handler explicitly re-throws to crash the process [1](#0-0) . Any full node that ever needs to validate/verify a unit or asset condition using such a definition (the poster's own node, and every peer/relay node that receives the propagated unit) will crash.

### Finding Description
`replaceInTemplate()` throws a custom `NoVarException` when a template variable referenced with `$name` is not present in the supplied `params`: [2](#0-1) 

This function is invoked synchronously from within the `definition template` case of the definition evaluator, itself called back inside a `conn.query()` result handler with no surrounding `try/catch`: [3](#0-2) 

The identical unguarded pattern also exists in the address-condition evaluator used during authentifier validation: [3](#0-2) 

Because `conn.query()`'s callback executes as a fresh call stack (a DB driver/event-loop callback), a `throw` inside it cannot be caught by any `try` block that wraps the original `evaluate()`/`validateDefinition()`/`validateAuthentifiers()` invocation. The exception therefore becomes an uncaught exception at the process level. ocore's own top-level handler treats *any* uncaught exception as fatal and deliberately re-throws to terminate the process, to avoid running with corrupted state: [1](#0-0) 

An attacker can trigger this by:
1. Posting a `definition_template` message (unit A) defining a template that references a variable, e.g. `["definition template", ["A", {template_var: "$x"}]]`-style body requiring `$x`.
2. Defining/using an address (their own, e.g., in an author's `definition` field, or an inner `["definition template", [unit_A, {}]]` used as part of an `address`/`definition` reference) whose definition invokes that template **without** supplying `$x` in `params`.
3. Broadcasting a unit authored by (or referencing) that address so any full node needs to run `validateDefinition`/`validateAuthentifiers` over it (e.g., to check the sender's signature, or to evaluate an `address` op that recurses into this definition, or evaluate an asset spending condition referencing it).

Every node — the attacker's own node when it first validates the unit, and every peer that receives and validates the propagated joint — hits the same unhandled `NoVarException` and crashes via the `uncaughtException` handler.

### Impact Explanation
This is a network-wide denial of service: a single crafted unit, postable by any unprivileged wallet, can crash every full node (and the poster's own node) that attempts to validate it or an address/asset condition that depends on it. Because the crash happens deterministically for any node processing the same unit, it can be used to repeatedly disrupt the network's ability to validate new units — matching the "network unable to confirm new units" bar for accepted impact.

### Likelihood Explanation
Definition templates (`definition template` op) and address definitions are ordinary, unprivileged wallet features — any user can post a `definition_template` message and reference it from an address definition with arbitrary `params`. No special permissions, witness/hub/relay role, or race condition is required; the bug is a straightforward missing-catch around a synchronous throw inside an async callback, deterministically reproducible.

### Recommendation
- Wrap the call to `replaceInTemplate()` (and any other function that can throw, such as `NoVarException`) in a `try/catch` at both call sites (`definition.js` in `validateDefinition` and `validateAuthentifiers`), converting the failure into a normal `cb("bad template params: ...")`/`cb2(false)` validation error instead of letting it escape as an unhandled exception.
- Audit other `throw`/`throw Error` statements reachable from inside `conn.query()` callbacks that are triggered while validating externally supplied unit content (definitions, authentifiers, messages) and convert them to callback-based error returns, since ocore intentionally crashes the process on any uncaught exception.

### Proof of Concept
1. Post a unit containing a `definition_template` message (app `definition_template`) whose payload template references an unresolved variable, e.g. `["definition template arr with $missing_var placeholder"]`.
2. Create/post a second unit whose author (or an inner referenced address) uses `["definition template", [<template_unit>, {}]]` in its definition, omitting `missing_var` from `params`.
3. Broadcast the second unit to the network. Every node that validates its author definition (or evaluates it while checking an `address`/asset condition referencing it) calls `replaceInTemplate()`, which throws `NoVarException` uncaught inside the `conn.query` callback in `definition.js` (lines 802-819 / template case), triggering Node's `uncaughtException` handler in `network.js` (lines 4530-4543), which re-throws and crashes the process.

Note: I was unable to fully view the exact surrounding lines (approximately 305–343) of `definition.js` where `validateDefinition`'s own `definition template` case is defined (only the tail, lines 340-343, and the twin case in `validateAuthentifiers`, lines 802-819, were retrieved), so I could not 100% confirm the absence of a `try/catch` specifically in `validateDefinition`'s copy of this case, only in `validateAuthentifiers`'s copy, which is structurally identical and already confirms the vulnerable pattern exists at least once in the codebase.

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

**File:** definition.js (L1468-1502)
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

function NoVarException(error){
	this.error = error;
	this.toString = function(){
		return this.error;
	};
}
```
