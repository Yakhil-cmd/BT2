### Title
In-memory `systemVars` (op_list / threshold_size / tps params) is not reverted on rollback of the MCI that stabilized it, causing stale protocol-parameter state - ([File: main_chain.js])

### Summary
`countVotes()` in `main_chain.js` mutates the module-level `storage.systemVars` cache directly (via `unshift`) as a side effect of stabilizing an MCI, in the same code path that later performs a SQL `COMMIT`/`ROLLBACK` in `writer.js`. If the surrounding `saveJoint()` transaction is rolled back after `countVotes()` already ran, the DB write to the `system_vars` table is undone, but the in-memory `storage.systemVars` mutation is not, and `storage.resetMemory()` (the function invoked specifically to resynchronize memory with the DB after a rollback) never resets it. This is the same bug class as the reported L2-upgrade issue: a height-gated protocol value is written into a long-lived cache before its triggering unit/block is guaranteed final, and is never rolled back if that trigger is reverted, so later processing keeps using a value that should never have taken effect (or takes effect one MCI early/late relative to the real chain state).

### Finding Description
`countVotes()` computes new values for governance-controlled system parameters (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) whenever an MCI carrying a `system_vote_count` message is stabilized, and immediately pushes the result into the in-memory cache: [1](#0-0) 
This happens inside `markMcIndexStable()`, which runs as part of `main_chain.updateMainChain()`: [2](#0-1) 

`updateMainChain()` is invoked from `writer.js`'s `saveJoint()` as one step in an `async.series(arrOps, ...)` pipeline, and critically, a `preCommitCallback` step (or any other step) can still run and fail **after** `updateMainChain()` (and therefore `countVotes()`) has already executed: [3](#0-2) 

If `err` is set at that point, the surrounding SQL transaction is rolled back and `storage.resetMemory(conn)` is called specifically to undo any in-memory state that no longer matches the (rolled-back) DB: [4](#0-3) 

However, `resetMemory()` only resets unstable/stable unit caches and `min_retrievable_mci`; it never re-reads or resets `storage.systemVars`: [5](#0-4) 

`storage.systemVars` is populated at startup from the `system_vars` table via `initSystemVars()`: [6](#0-5) 

and is read directly by validation/fee logic afterwards, e.g. `getSystemVar()` / `getOpList()` / `getOversizeFee()`, all of which trust the in-memory array to reflect DB state: [7](#0-6) 

Because the `vote_count_mci` write to `system_vars` is transactional but the `unshift()` into `storage.systemVars[subject]` is not, a rollback leaves a "phantom" entry in memory that was never durably committed to the DB. This node will keep applying that phantom value (potentially the wrong OP list, wrong `threshold_size`, wrong TPS fee constants) to *all subsequent* unit validation, fee calculation, and MC-stability determination, until the process restarts and `initCaches()`/`initSystemVars()` re-syncs from the DB.

### Impact Explanation
`systemVars` values directly gate: (1) the common Order Provider (OP/witness) list used for MC-stability/witness-set determination (`getOpList`), and (2) `threshold_size`/`base_tps_fee`/`tps_interval`/`tps_fee_multiplier` used to compute `oversize_fee`/`tps_fee`, which are consensus-critical fields validated on every v4+ unit (`validation.js`, `getOversizeFee`). A node that retains a phantom, never-committed value will validate/reject units differently from peers that never ran the failed transaction (or that already restarted), producing node disagreement on unit validity and, transitively, on MC stability — this can partition validating nodes or allow a locally-accepted unit that peers reject (or vice versa), which is a "node disagreement on validity or stability" outcome.

### Likelihood Explanation
Exploitability doesn't require a malicious peer/node: any legitimate `system_vote_count` unit that stabilizes an MCI triggers `countVotes()`, and any subsequent failure in the same `saveJoint()` pipeline (e.g., a failing `preCommitCallback`, or any other operation added to `arrOps` after `updateMainChain`) rolls back the transaction while leaving `storage.systemVars` polluted. Such errors are a normal part of unit processing (concurrent conflicting units, AA trigger side effects, DB constraint issues), so the divergence window is realistically reachable, though it requires the specific timing of "vote-count MCI stabilizes, then a later step in the same write aborts" — making it a real but not always-guaranteed occurrence, consistent with Medium/High severity.

### Recommendation
Make the `storage.systemVars` mutation transactional/consistent with the DB write:
- Defer the `storage.systemVars[subject].unshift(...)` mutation until after the enclosing SQL transaction is confirmed committed (e.g., perform it in the `saved_unit`/`saved_unit-<unit>` event handler or right after `commit_fn("COMMIT", ...)` succeeds), rather than inline inside `countVotes()`.
- Alternatively, have `storage.resetMemory()` also call `initSystemVars(conn)` again (or otherwise pop/rollback any entries whose `vote_count_mci` doesn't match a value now present in the DB) so that a rollback always restores `storage.systemVars` to match persisted state, mirroring how `l2SystemContractsUpgradeBlockNumber` should be reset on `revertBlocks` in the referenced report.

### Proof of Concept
1. Construct/accept a unit carrying `system_vote_count` for `op_list` (or any numerical subject) that causes its MCI to stabilize; this synchronously runs `countVotes()` and mutates `storage.systemVars.op_list` (or the numeric subject array) via `unshift`, per `main_chain.js:1866-1912`.
2. In the same `saveJoint()` call, arrange for a later `arrOps` step (e.g. a supplied `preCommitCallback`, as used by higher-level callers such as AA/trigger composition) to fail, so `async.series(arrOps, ...)` in `writer.js:662` receives a truthy `err`.
3. `commit_fn("ROLLBACK", ...)` runs, and because `err` is set, `writer.js:708-712` calls `storage.resetMemory(conn)`.
4. Inspect `storage.systemVars` after this call: the entry pushed in step 1 is still present, even though the corresponding `system_vars` row was never committed to the DB (rolled back). Subsequent calls to `storage.getOpList()`/`storage.getOversizeFee()`/`storage.getSystemVar()` on this node will use the phantom value, diverging from peers/DB.

### Citations

**File:** main_chain.js (L1657-1667)
```javascript
					async function() {
						// vote count must be processed last, after all system_votes, and once for the entire mci
						for (let subject of voteCountSubjects)
							await countVotes(conn, mci, subject);
						// next op
						updateRetrievable();
					}
				);
			}
		);
	}
```

**File:** main_chain.js (L1900-1912)
```javascript
			if (value === undefined)
				throw Error(`no median value for ` + subject);
			storage.systemVars[subject].unshift({ vote_count_mci: mci, value, is_emergency });
			break;
		
		default:
			throw Error("unknown subject in countVotes: " + subject);
	}
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
	await conn.query(conn.dropTemporaryTable('voter_balances'));
	eventBus.emit('system_vars_updated', subject, value);
```

**File:** writer.js (L646-662)
```javascript
							arrOps.push(function(cb){
								console.log("updating MC after adding "+objUnit.unit);
								main_chain.updateMainChain(conn, batch, null, objUnit.unit, objValidationState.bAA, (_arrStabilizedMcis, _bStabilizedAATriggers) => {
									arrStabilizedMcis = _arrStabilizedMcis;
									bStabilizedAATriggers = _bStabilizedAATriggers;
									cb();
								});
							});
						}
						if (preCommitCallback)
							arrOps.push(function(cb){
								console.log("executing pre-commit callback");
								preCommitCallback(conn, cb);
							});
					}
					// only preCommitCallback can return err
					async.series(arrOps, function(err){
```

**File:** writer.js (L702-713)
```javascript
							commit_fn(err ? "ROLLBACK" : "COMMIT", async function(){
								var consumed_time = Date.now()-start_time;
								profiler.add_result('write', consumed_time);
								console.log((err ? (err+", therefore rolled back unit ") : "committed unit ")+objUnit.unit+", write took "+consumed_time+"ms");
								profiler.stop('write-sql-commit');
								profiler.increment();
								if (err) {
									var headers_commission = require("./headers_commission.js");
									headers_commission.resetMaxSpendableMci();
									delete storage.assocUnstableMessages[objUnit.unit];
									await storage.resetMemory(conn);
								}
```

**File:** storage.js (L1132-1166)
```javascript
function getSystemVar(subject, mci) {
	for (let { vote_count_mci, value } of systemVars[subject])
		if (mci > vote_count_mci)
			return value;
	throw Error(subject + ` not found for mci ` + mci);
}

function getOpList(mci) {
	return getSystemVar('op_list', mci);
}

function exp(x) {
	return new Decimal(x).exp().toNumber();
}

function getOversizeFee(objUnitOrSize, mci, bAA) {
	let size;
	if (typeof objUnitOrSize === "number")
		size = objUnitOrSize; // must be already without temp data fee
	else if (typeof objUnitOrSize === "object") {
		if (!objUnitOrSize.headers_commission || !objUnitOrSize.payload_commission)
			throw Error("no headers or payload commission in unit");
		// AA-generated units pay the oversize fee based on the unit size excluding its payment messages to avoid swelling the fee while spending dust outputs
		const payload_commission = (bAA && mci >= constants.pemCurvesFixMci)
			? objectLength.getTotalPayloadSize({ ...objUnitOrSize, messages: objUnitOrSize.messages.filter(message => message.app !== 'payment') })
			: objUnitOrSize.payload_commission;
		size = objUnitOrSize.headers_commission + payload_commission - objectLength.getPaidTempDataFee(objUnitOrSize);
	}
	else
		throw Error("unrecognized 1st arg in getOversizeFee");
	const threshold_size = getSystemVar('threshold_size', mci);
	if (size <= threshold_size)
		return 0;
	return Math.ceil(size * (exp(size / threshold_size - 1) - 1));
}
```

**File:** storage.js (L2474-2484)
```javascript
async function initSystemVars(conn) {
	const rows = await conn.query("SELECT subject, value, vote_count_mci, is_emergency FROM system_vars ORDER BY vote_count_mci DESC");
	if (rows.length === 0)
		throw Error("no system vars");
	for (let { subject, value, vote_count_mci, is_emergency } of rows)
		systemVars[subject].push({ vote_count_mci, value: subject === 'op_list' ? JSON.parse(value) : +value, is_emergency });
	for (let subject in systemVars)
		if (systemVars[subject].length === 0)
			throw Error(`no ${subject} system vars`);
	console.log('system vars', systemVars);
}
```

**File:** storage.js (L2521-2530)
```javascript
function resetMemory(conn, onDone){
	if (!onDone)
		return new Promise(resolve => resetMemory(conn, resolve));
	resetUnstableUnits(conn, function(){
		resetStableUnits(conn, function(){
			min_retrievable_mci = null;
			initializeMinRetrievableMci(conn, onDone);
		});
	});
}
```
