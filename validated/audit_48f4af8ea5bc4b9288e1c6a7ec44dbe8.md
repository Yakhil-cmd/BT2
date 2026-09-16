### Title
Storage-size accounting mismatch causes AA state updates to hard-crash instead of bouncing - (File: `aa_composer.js`)

### Summary
The reported Trident bug is a class of "split accumulator" defect: a global counter (`feeGrowthGlobal`) is compared against the sum of two independently-updated partial counters (`feeGrowthBelow`/`feeGrowthAbove`) that are not guaranteed to sum to a value ≤ the global counter, so the subtraction underflows and reverts, permanently blocking mint/burn on the range. The reachable analog in ocore is `updateStorageSize()` in `aa_composer.js`, which reconstructs a delta for the AA's global `storage_size` counter from a *sum of independently tracked per-state-variable deltas* (`state.original_old_value`, `getValueSize`), rather than directly comparing against the authoritative on-disk value.

### Finding Description
`updateStorageSize()` in `aa_composer.js` [1](#0-0)  computes `delta_storage_size` by iterating over `stateVars[address]` and, for every variable marked `updated`, adding `newSize - getValueSize(state.original_old_value)` (or subtracting the full old size on deletion). This is exactly the "sum of partial deltas must equal the true global change" pattern that broke in the Trident bug: the global `storage_size` value stored in `aa_addresses` is only ever mutated through this delta reconstruction, never re-derived from the authoritative full state. If any state variable's `original_old_value`/size bookkeeping is inconsistent with what is actually persisted (e.g., due to values read/written across different messages of the same trigger, secondary triggers touching the same address, or numeric-to-string size differences such as `Decimal` subnormal rounding noted in `getValueSize` — `value.toNumber().toString().length`, which can differ from the `getTypeAndValue` serialization used when actually persisting via `saveStateVars()` [2](#0-1) ), the reconstructed `delta_storage_size` can diverge from the real size change.

When that divergence causes `new_storage_size` to be computed as negative, the code does not bounce gracefully — it throws:
```
if (new_storage_size < 0)
    throw Error("storage size would become negative: " + new_storage_size);
``` [3](#0-2) 

This is a raw, uncaught `throw`, not a `bounce()`/`cb(err)` path like the other checks in the same function (e.g., the byte-balance check right below it uses `return cb(...)`). This mirrors the Trident issue precisely: a value derived from summing independently-maintained partial trackers is subtracted from (or compared against) the "global" tracked value without a guarantee that the components stay within bounds, and when the invariant breaks, the code takes the revert/crash path instead of handling it as an ordinary validation failure.

### Impact Explanation
If this arithmetic invariant is violated for any AA address (e.g., through interaction of primary+secondary triggers or state var read/write ordering within `handleTrigger`), the `throw Error(...)` is not caught by the surrounding trigger-bounce machinery the way `cb(err)` failures are — it propagates as an unhandled exception during unit processing. Because AA trigger execution happens as part of stabilization/unit processing (see `writer.js`'s `aa_composer.handleAATriggers()` call during stabilization) [4](#0-3) , an uncaught exception here can crash node processing for that AA, effectively freezing further triggers/funds for that address (fund-freezing / node-unable-to-process-further-units impact), which matches the "funds get stuck" impact class of the original H-09 finding.

### Likelihood Explanation
Likelihood is lower-confidence relative to a fully proven exploit: I could not fully trace every code path that sets/reads `state.original_old_value` and `state.updated` (that logic lives in `formula/evaluation.js`, and I was not able to fully inspect its full definition within the available search budget) to construct a concrete state-variable-manipulation sequence guaranteed to desynchronize the accumulator. The pattern (delta-of-deltas reconstruction of a persisted global counter, guarded by a hard `throw` on invariant violation) is present and directly analogous to the reported bug class, but I cannot claim a verified end-to-end PoC of the divergence itself from the indexed code alone.

### Recommendation
Replace the delta-reconstruction of `storage_size` with a direct, idempotent recomputation from the full set of persisted state-var sizes for the address whenever discrepancies are possible, or make the negative/overflow case a normal bounce path (`return cb(...)`) instead of an uncaught `throw`, so that an accounting mismatch fails the individual trigger safely rather than crashing unit processing.

### Proof of Concept
Not independently verified end-to-end from the indexed code; the report is based on identifying the structurally analogous "sum-of-partial-accumulators vs. global-counter, guarded by an unhandled revert/throw" pattern in `updateStorageSize()`, per the instructions to use the external report only as a bug-class hint. A concrete trigger sequence that forces `state.original_old_value` bookkeeping to diverge from the actual persisted `aa_addresses.storage_size` would need to be constructed by tracing `formula/evaluation.js`'s state-var read/write instrumentation in full, which exceeded the available exploration budget.

### Citations

**File:** aa_composer.js (L1505-1516)
```javascript
	function getTypeAndValue(value) {
		if (typeof value === 'string')
			return 's\n' + value;
		else if (typeof value === 'number')
			return 'n\n' + value;
		else if (Decimal.isDecimal(value))
			return 'n\n' + value.toNumber(); // drop the excessive precision in subnormals
		else if (value instanceof wrappedObject)
			return 'j\n' + string_utils.getJsonSourceString(value.obj, true);
		else
			throw Error("state var of unknown type: " + value);	
	}
```

**File:** aa_composer.js (L1531-1571)
```javascript
	function updateStorageSize(cb) {
		if (bBouncing || trigger_opts.bAir)
			return cb();
		var delta_storage_size = 0;
		var addressVars = stateVars[address] || {};
		for (var var_name in addressVars) {
			var state = addressVars[var_name];
			if (!state.updated)
				continue;
			if (state.value === false) { // false value signals that the var should be deleted
				if (state.original_old_value !== undefined)
					delta_storage_size -= var_name.length + getValueSize(state.original_old_value);
			}
			else {
				try {
					var newSize = getValueSize(state.value);
				}
				catch (e) {
					console.log("failed to get size of new value of state var " + var_name + ": ", e);
					return cb("invalid new value of state var " + var_name);
				}
				if (newSize > constants.MAX_STATE_VAR_VALUE_LENGTH)
					return cb(`state var value too long: ${newSize}`);
				if (state.original_old_value !== undefined)
					delta_storage_size += newSize - getValueSize(state.original_old_value);
				else
					delta_storage_size += var_name.length + newSize;
			}
		}
		console.log('storage size = ' + storage_size + ' + ' + delta_storage_size + ', byte_balance = ' + byte_balance);
		var new_storage_size = storage_size + delta_storage_size;
		if (new_storage_size < 0)
			throw Error("storage size would become negative: " + new_storage_size);
		if (byte_balance < new_storage_size && new_storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci)
			return cb("byte balance " + byte_balance + " would drop below new storage size " + new_storage_size);
		if (delta_storage_size === 0)
			return cb();
		conn.query("UPDATE aa_addresses SET storage_size=? WHERE address=?", [new_storage_size, address], function () {
			cb();
		});
	}
```

**File:** writer.js (L724-727)
```javascript
								if (bStabilizedAATriggers && !err) {
									console.log(`executing AA triggers`);
									const aa_composer = require("./aa_composer.js");
									await aa_composer.handleAATriggers();
```
