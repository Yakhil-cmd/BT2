### Title
Unchecked null dereference on unresolved cross-AA call to a base AA in a chained trigger - ([File: aa_composer.js])

### Summary
`handleTrigger()` in `aa_composer.js` resolves a parameterized ("template") AA by looking up its `base_aa` definition via `storage.readAADefinition()` and immediately dereferencing the result. If the lookup returns `null`/`undefined`, the code throws an uncaught `Error` deep inside the AA-trigger execution pipeline rather than gracefully bouncing, mirroring the CVE-2020-27795 pattern where a lookup function (`r_anal_get_fcn_in`) can return null and the caller (`ensure_fcn_range`) unconditionally dereferences it, crashing the process.

### Finding Description
When a trigger targets a parameterized AA, `handleTrigger()` reads the base AA definition and unconditionally throws if it's missing, instead of bouncing the trigger cleanly: [1](#0-0) 

```
if (template.base_aa) { // parameterized AA
    ...
    storage.readAADefinition(conn, template.base_aa, mci, function (arrBaseDefinition) {
        if (!arrBaseDefinition)
            throw Error("base AA not found: " + template.base_aa);
        ...
        handleTrigger(trigger_opts);
    });
    return;
}
```

This `throw` executes inside an asynchronous DB-callback deep in the AA execution stack (invoked from `handlePrimaryAATrigger`/`handleSecondaryTriggers`, themselves invoked from `main_chain.stabilizeMci()` during MCI stabilization). Unlike ordinary validation errors that are surfaced via `callback(err)`/bounce, this is a synchronous `throw` with no surrounding `try/catch`, so it propagates as an uncaught exception in that stack frame. In Node.js, an uncaught exception thrown from inside an I/O callback (this one runs inside a `db.query`/`conn.query` callback chain, itself nested inside `stabilizeMci`) is not caught by the caller's promise chain and crashes the process (`process.on('uncaughtException')` is not otherwise guarding this path in `ocore`), exactly analogous to a segfault-class denial: unprivileged input triggers a hard node crash instead of a handled error.

Reachability: an attacker does not need special privileges — any unprivileged user can:
1. Define an AA `X` whose template has `base_aa` pointing at address `Y`.
2. Ensure at validation time `Y` is/looks like a valid AA (so `validateAADefinition`/`aa_validation.js` passes, e.g., `arrBaseDefinition[1].messages` present) — or exploit a race/edge condition where `Y`'s AA status changes between the trigger being queued (`aa_triggers` table) and the trigger actually executing at a later mci (`storage.readAADefinition(conn, template.base_aa, mci, ...)` uses the *current* mci at execution time, not necessarily the same view used at validation time via `objValidationState.aa_mci`/`top_mci`).
3. Post a payment/trigger unit addressed to `X`.

When the trigger fires (potentially at a different mci or after cache/definition-visibility changes), `readAADefinition` can legitimately return `null` for `template.base_aa`, hitting the `throw` and crashing the node process during MCI stabilization — a shared, unprivileged trigger path that every node evaluates identically.

Note: `validation.js`'s handling of top-level `definition` messages that create parameterized AAs already validates that `base_aa` resolves to a real AA at unit-validation time: [2](#0-1) 

```
storage.readAADefinition(conn, template.base_aa, top_mci, function (arrBaseDefinition) {
    if (!arrBaseDefinition)
        return callback("base AA not found");
    if (!arrBaseDefinition[1].messages)
        return callback("base AA must be a regular AA");
    callback();
});
```

However, `handleTrigger()`'s runtime lookup at execution time is not guaranteed to be consistent with the validation-time check, since it re-reads at a possibly-different `mci` context (execution can occur well after validation, and via `estimatePrimaryAATrigger`/light `dry_run_aa`, at `mci=null` i.e. current unstable state) — creating a window where the assumption "base_aa always resolves" can be violated and the unchecked `throw` is hit.

### Impact Explanation
An uncaught `throw` in the middle of `handlePrimaryAATrigger`/`handleSecondaryTriggers`, which run inside `main_chain.stabilizeMci()` right after an MCI is marked stable (`count_aa_triggers > 0` → `aa_composer.handleAATriggers()`), crashes the full node process while it holds the `aa_triggers` mutex and an open DB transaction. This halts stabilization and AA trigger processing network-wide for any node that reaches this mci with this trigger queued, i.e., "a network unable to confirm new units" until the offending trigger/data is manually purged — the same availability impact class validated as in-scope (node disagreement on validity/stability, or the network being unable to progress), directly analogous to a crash caused by unchecked null in the reported CVE.

### Likelihood Explanation
Likelihood is Medium: the primary safety net is the validation-time check in `validation.js` (`"base AA not found"` bounce), which prevents *most* naive attempts. But the runtime resolution in `aa_composer.js` uses a fresh `readAADefinition` call gated by the *execution*-time mci/context (via `estimatePrimaryAATrigger`, `dryRunPrimaryAATrigger`, or delayed secondary-trigger execution at a later stable mci than validation), so an attacker who can construct a timing/definition-visibility discrepancy (e.g., base AA temporarily unconfirmed/rolled back in local mempool view, or via `light/dry_run_aa`/estimation APIs called with attacker-supplied unvalidated `arrDefinition`) can hit the unchecked `throw` without the earlier bounce path intervening.

### Recommendation
Replace the unconditional `throw Error("base AA not found: " + template.base_aa)` in `aa_composer.js`'s `handleTrigger()` with a graceful bounce (invoke the existing `bounce()`/`revert()` machinery used elsewhere in the same function for error conditions) so that an unresolved `base_aa` at execution time results in a bounced/failed AA response rather than an uncaught exception that can crash the node. Additionally, ensure the mci used for the runtime `readAADefinition(conn, template.base_aa, mci, ...)` lookup is consistent with the mci that was used to validate `base_aa` resolution, to close the discrepancy window between validation-time and execution-time checks.

### Proof of Concept
1. Define AA `Y` (a valid regular AA with `messages`).
2. Define AA `X` = `['autonomous agent', { base_aa: Y_address, params: {...} }]`, which validates successfully because at validation time `Y` resolves via `storage.readAADefinition`.
3. Arrange for `Y`'s definition to become unresolvable via `storage.readAADefinition(conn, Y_address, mci, ...)` at the specific `mci` used at trigger-execution time — for example by invoking the trigger through `estimatePrimaryAATrigger`/`light/dry_run_aa` (`network.js` `light/dry_run_aa` handler, which calls `aa_composer.dryRunPrimaryAATrigger` using `mci=null`/unstable context) with a definition graph where `base_aa` visibility differs from the confirmed state, or by sending the trigger just as `Y`'s own AA-defining unit becomes unconfirmed/rolled back.
4. Send a payment/trigger unit to `X`; when `handleTrigger()` executes and hits `template.base_aa` resolution returning falsy, it throws an uncaught `Error`, crashing the executing node process during AA trigger processing. [1](#0-0)

### Citations

**File:** aa_composer.js (L433-444)
```javascript
	if (template.base_aa) { // parameterized AA
		if (params && Object.keys(params).length > 0)
			throw Error("unexpected params");
		storage.readAADefinition(conn, template.base_aa, mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + template.base_aa);
			console.log("redirecting to base AA " + template.base_aa + " with params " + JSON.stringify(template.params));
			trigger_opts.params = template.params;
			trigger_opts.arrDefinition = arrBaseDefinition;
			handleTrigger(trigger_opts);
		});
		return;
```

**File:** validation.js (L1773-1780)
```javascript
				// else parameterized AA
				storage.readAADefinition(conn, template.base_aa, top_mci, function (arrBaseDefinition) {
					if (!arrBaseDefinition)
						return callback("base AA not found");
					if (!arrBaseDefinition[1].messages)
						return callback("base AA must be a regular AA");
					callback();
				});
```
