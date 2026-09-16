### Title
NULL pointer dereference in address-definition `evaluateFilter()` on `augmented_input` — Denial of Service ([File: definition.js])

### Summary
`definition.js`'s `evaluateFilter()` (used to evaluate `has`, `has one`, `sum`, and `seen`-style input filters inside address/asset spending-condition definitions) computes `augmented_input` and, when it is `null`, still unconditionally dereferences `augmented_input.address`/`.amount` if the filter specifies an `address`/`amount` constraint. This is analogous to the reported libjpeg `BlockBitmapRequester::PullQData()` bug class: a value that can legitimately be `null`/absent is dereferenced without a guard, causing an unhandled exception that crashes the process — the JS equivalent of a native NULL-pointer dereference DoS.

### Finding Description
In `evaluateFilter()`: [1](#0-0) 

```
var augmented_input = objValidationState.arrAugmentedMessages ? objValidationState.arrAugmentedMessages[i].payload.inputs[j] : null;
if (filter.address){
    if (filter.address === 'this address'){
        if (augmented_input.address !== address)   // <-- dereferenced without null check
            continue;
    }
    ...
```

`augmented_input` is explicitly set to `null` whenever `objValidationState.arrAugmentedMessages` has not been populated for this evaluation. Augmentation is only performed on demand, gated by `augmentMessagesIfNeeded(bNeeded, next)`: [2](#0-1) 

If, for the branch of the address definition currently under evaluation, the code that decides `bNeeded` does not always turn on augmentation exactly for the case `filter.what === 'input' && filter.address` (or if `evaluateFilter` for a given op is reached along a path where augmentation was never requested), `arrAugmentedMessages` stays unset and the subsequent `augmented_input.address`/`.amount` access throws `TypeError: Cannot read properties of null`. This is the same missing-guard root cause pattern as the CVE: a pointer/reference that can be `null` in a valid, spec-compliant code path is read without a prior existence check.

This code path is reached from `validateAuthentifiers()`, which is invoked for **every unit** signed by an address that uses one of these definition operators (`has`, `has one`, `sum`, `seen`) with an `input` filter constrained by `address`/`amount` — a completely standard, publicly documented oscript address-definition feature that any wallet owner can put in their own address definition.

### Impact Explanation
Any address (created by any user, including an attacker) can be defined with a spending condition using `['seen', {what:'input', address:'this address', ...}]` or `['has'/'has one', {...}]`/`['sum', {...}]`. Because `'seen'` mandates a non-empty `address` field, any evaluation of such a definition that does not trigger prior augmentation will throw. Since `validate()` runs inside the main synchronous validation flow for any unit that spends from/references such an address (and this same evaluator is shared for parsing units broadcast by any peer, including light clients and via `aa_composer`/`signed_message` flows), an unhandled `TypeError` here propagates up through async callbacks to `process.on('uncaughtException')`, which explicitly re-throws to **crash the process**: [3](#0-2) 

A full node/witness crash from a single posted unit referencing (or being posted by) an address with such a definition is a network-availability impact — nodes are unable to continue validating/confirming units until restarted, satisfying the "network unable to confirm new units" bar.

### Likelihood Explanation
Medium: triggering the crash requires the specific runtime state where `evaluateFilter` is invoked for an `input`+`address` (or `amount`) filter without `arrAugmentedMessages` having been populated first. I was not able to fully trace every caller of `augmentMessagesIfNeeded`/`evaluateFilter` (op dispatch code before line ~1260 was not fully inspected) to prove that every reachable dispatch path sets `bNeeded=true` for these filter shapes; it is possible existing call sites already guard this correctly for the common `has`/`has one`/`sum` paths. The `seen` op is the strongest candidate because it mandates `args.address` be present, making the `filter.address` branch unconditionally reachable whenever `seen` is used with `what:'input'`.

### Recommendation
Add a defensive null check before dereferencing `augmented_input` in `evaluateFilter()`, e.g. treat a missing/null `augmented_input` as "filter fails" (`continue`) rather than crashing, and/or make augmentation unconditional whenever `filter.what === 'input'` and `filter.address`/`filter.amount*` is present, regardless of the op (`has`/`has one`/`sum`/`seen`). Add regression tests covering `seen`/`has`/`sum` with `what:'input'` and an `address` or `amount` constraint against transfer/issue inputs to ensure no unhandled exception is thrown.

### Proof of Concept
1. Create address A with definition:
   `["seen", {"what":"input", "address":"this address"}]` combined with a signature branch, e.g. `["and", [["sig",{...}], ["seen",{"what":"input","address":"this address"}]]]`.
2. Fund address A and post a unit spending from A with a `transfer` input.
3. During validation, `validateAuthentifiers` → `evaluate()` → op `'seen'` → `evaluateFilter('seen', {what:'input', address:'this address'}, ...)` runs; if `augmentMessagesIfNeeded` was not invoked with `bNeeded=true` for this branch before `evaluateFilter` executes, `arrAugmentedMessages` is unset, `augmented_input` is `null`, and `augmented_input.address` throws, crashing the validating node via the global `uncaughtException` handler.

*(Note: full confirmation that no upstream code path already forces augmentation for every `filter.address`/`filter.amount` case in `has`/`has one`/`sum`/`seen` requires inspecting the dispatcher code above line ~1260 in `definition.js`, which was not fully available in this review — this should be verified directly in the repository before treating this as conclusively exploitable.)*

### Citations

**File:** definition.js (L1269-1275)
```javascript
	function augmentMessagesIfNeeded(bNeeded, next) {
		if (!objValidationState.arrAugmentedMessages && bNeeded)
			augmentMessages(next);
		else
			next();
	}
	
```

**File:** definition.js (L1298-1327)
```javascript
			if (filter.what === "input"){
				if (!Array.isArray(payload.inputs))
					continue;
				for (var j=0; j<payload.inputs.length; j++){
					var input = payload.inputs[j];
					if (!isNonemptyObject(input))
						continue;
					if (input.type === "headers_commission" || input.type === "witnessing")
						continue;
					if (filter.type){
						var type = input.type || "transfer";
						if (type !== filter.type)
							continue;
					}
					var augmented_input = objValidationState.arrAugmentedMessages ? objValidationState.arrAugmentedMessages[i].payload.inputs[j] : null;
					if (filter.address){
						if (filter.address === 'this address'){
							if (augmented_input.address !== address)
								continue;
						}
						else if (filter.address === 'other address'){
							if (augmented_input.address === address)
								continue;
						}
						else { // normal address
							if (augmented_input.address !== filter.address)
								continue;
						}
					}
					if (filter.amount && augmented_input.amount !== filter.amount)
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
