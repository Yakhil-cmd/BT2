### Title
Unconditional `throw Error()` on negative AA storage-size/balance invariant crashes full nodes - (File: `aa_composer.js`)

### Summary
`aa_composer.js` mirrors the Xen Xenstored bug class from ALPINE‑CVE‑2023‑34323: it tracks a per-address accounting quantity (AA `storage_size`, and separately `aa_balances`) incrementally across trigger executions, and instead of gracefully rejecting a bad state, it uses an unconditional `throw Error(...)` that assumes the accounted value can never go negative/mismatched. Just like the Xenstored `assert()` on quota that crashes the daemon when accounting is temporarily/incorrectly negative, these `throw` statements are not caught anywhere in the trigger-processing call chain and will crash the whole ocore full-node process when hit.

### Finding Description
In `updateStorageSize()`, the per-AA-address byte-storage accounting is updated incrementally from the delta of state-var sizes computed for the current trigger: [1](#0-0) 

```
var new_storage_size = storage_size + delta_storage_size;
if (new_storage_size < 0)
    throw Error("storage size would become negative: " + new_storage_size);
```

This is exactly the CVE-2023-34323 pattern: the code assumes the accounted quantity (`storage_size`, populated from `aa_addresses.storage_size` and adjusted by `getValueSize()`/`getTypeAndValue()` deltas) cannot go negative, and enforces that assumption with a hard `throw` rather than a bounce/handled error. `getValueSize()` for numeric/Decimal state vars deliberately drops precision (`value.toNumber().toString().length`, `aa_composer.js:1518-1529`), so the size recorded when a var was created can differ from the size computed when it is later deleted/overwritten, which is precisely the kind of "accounting can end up negative because of an assumption violated elsewhere" bug class described in the advisory.

The same throw-on-invariant-violation pattern also exists in the periodic AA integrity checks that run against every full node's database, driven purely by units/triggers that have already been processed from the network: [2](#0-1) [3](#0-2) 

```
if (rows.length > 0)
    throw Error("checkBalances failed: sql:\n" + sql + "\n\nrows:\n" + JSON.stringify(rows, null, '\t'));
```

Both `checkStorageSizes()` and `checkBalances()` are scheduled via `setInterval` on every non-light node (`aa_composer.js:2072-2079`) and will `throw` (crashing the node) as soon as the derived accounting (`aa_balances`/`storage_size`) diverges from the ground truth computed from `outputs`/kvstore contents. The existence of `reintroduceBalanceBug()` (`aa_composer.js:2055-2069`), a hardcoded table of address-specific balance corrections for past discrepancies, is direct evidence that this exact accounting-can-diverge bug class has previously been exploitable/observed in production on this codebase — the same fragile-invariant condition the Xen CVE describes.

None of `handleTrigger`'s internal callbacks (`updateInitialAABalances`, `updateFinalAABalances`, `updateStorageSize`, `sendDummyUnit`, etc.) wrap these throws in `try/catch`; they execute inside asynchronous DB-callback continuations, so an uncaught exception here is not converted into a `bounce()`-style AA failure but propagates as a genuine uncaught JS exception, terminating the ocore process on every node that deterministically re-executes the same AA trigger/response (all full nodes evaluate AAs identically to agree on the DAG state).

### Impact Explanation
Because the `throw` fires deterministically for any full node that processes the same trigger/response chain (AA execution is required to be deterministic so all nodes agree on validity/state), a single crafted unit posted to an AA that drives its accounted `storage_size` or `aa_balances` to a value that violates the "must stay ≥ 0 / must match actual outputs" invariant will crash every full node in the network as they each independently process that unit. This matches the "network unable to confirm new units" impact bucket: nodes across the network would need to be manually restarted, and until code is fixed, the crashing unit continues to be present/reprocessed on catch-up, causing a rolling denial of confirmation.

### Likelihood Explanation
Reaching `updateStorageSize`'s throw requires an AA whose state-var lifecycle creates a size-accounting mismatch (e.g., via the documented precision-dropping `getValueSize()` for Decimal/number vars, or interplay between primary/secondary triggers and `original_old_value` restoration). Reaching `checkBalances`'/`checkStorageSizes`' throw only requires that any AA, anywhere in the system's history, produce a balance/storage-size divergence — evidenced by the pre-existing `reintroduceBalanceBug` patch list, which shows this has already happened for at least 14 addresses in production. This indicates the underlying accounting invariant is not perfectly maintained, making a fresh divergence plausible under attacker-influenced AA definitions (e.g., AAs handling asset issuance, send-all outputs, or precision-sensitive numeric state vars).

### Recommendation
- Replace the unconditional `throw Error(...)` guards in `updateStorageSize()` and `checkBalances()`/`checkStorageSizes()` with recoverable error handling (`bounce()` the triggering unit, or log-and-skip with alerting) instead of crashing the process, mirroring how the Xen fix replaced the `assert()` with tolerant handling of transient negative accounting.
- Audit `getValueSize()`/`getTypeAndValue()` for cases where the recorded size of a state var at creation time can differ from the size computed at deletion/update time (particularly Decimal→Number precision loss), and make the storage-size ledger exact/idempotent rather than delta-based.
- Ensure `checkBalances`/`checkStorageSizes` failures degrade to non-fatal alerts (e.g., disable AA processing for the affected address, or resync just that account) rather than aborting the whole daemon.

### Proof of Concept
Concrete exploitation requires crafting an AA definition/state-var sequence that drives `delta_storage_size` negative beyond `storage_size`, or a balance/output divergence detected by `checkBalances`. I could not fully enumerate, within the scope of this static review, the exact state-var sequence that forces `new_storage_size < 0` under current guard logic (this would need dynamic testing/fuzzing of `getValueSize()`/`getTypeAndValue()` precision-loss edge cases across create→update→delete cycles, and of `updateFinalAABalances` interplay with `assocDeltas`). The `reintroduceBalanceBug()` table is documented evidence that equivalent balance-accounting divergences have occurred previously on this exact codebase, supporting that the invariant is not unconditionally safe. Root cause and unconditional-throw locations are cited above with exact file/line references.

### Citations

**File:** aa_composer.js (L1560-1566)
```javascript
		console.log('storage size = ' + storage_size + ' + ' + delta_storage_size + ', byte_balance = ' + byte_balance);
		var new_storage_size = storage_size + delta_storage_size;
		if (new_storage_size < 0)
			throw Error("storage size would become negative: " + new_storage_size);
		if (byte_balance < new_storage_size && new_storage_size > FULL_TRANSFER_INPUT_SIZE && mci >= constants.aaStorageSizeUpgradeMci)
			return cb("byte balance " + byte_balance + " would drop below new storage size " + new_storage_size);
		if (delta_storage_size === 0)
```

**File:** aa_composer.js (L1918-1952)
```javascript
function checkStorageSizes() {
	mutex.lockOrSkip(['checkStorageSizes'], function (unlock) {
		db.takeConnectionFromPool(function (conn) { // block conection for the entire duration of the check
			var options = {};
			options.gte = "st\n";
			options.lte = "st\n\uFFFF";

			var assocSizes = {};
			var handleData = function (data) {
				var address = data.key.substr(3, 32);
				var var_name = data.key.substr(36);
				if (!assocSizes[address])
					assocSizes[address] = 0;
				assocSizes[address] += var_name.length + data.value.length - 2; // -2 for type and \n
			}
			var stream = kvstore.createReadStream(options);
			stream.on('data', handleData)
				.on('end', function () {
					conn.query("SELECT address, storage_size FROM aa_addresses", function (rows) {
						rows.forEach(function (row) {
							if (!assocSizes[row.address])
								assocSizes[row.address] = 0;
							if (row.storage_size !== assocSizes[row.address])
								throw Error("storage size mismatch on " + row.address + ": db=" + row.storage_size + ", kv=" + assocSizes[row.address]);
						});
						conn.release();
						unlock();
					});
				})
				.on('error', function (error) {
					throw Error('error from data stream: ' + error);
				});
		});
	});
}
```

**File:** aa_composer.js (L2040-2042)
```javascript
							if (rows.length > 0)
								throw Error("checkBalances failed: sql:\n" + sql + "\n\nrows:\n" + JSON.stringify(rows, null, '\t'));
							cb();
```
