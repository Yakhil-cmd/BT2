## Title
Race condition between `mci_became_stable` notification and transaction commit can expose watchers/AAs to stale data — ([File: main_chain.js])

### Summary
The Fuel-core fix (commit `b7e1c6e`) addressed a race where transaction-status notifications fired to subscribers before the corresponding receipts were durably committed to the off-chain database, so listeners querying "updated" data could see stale/empty results. Ocore has an analogous, self-documented race: the `mci_became_stable` event (and the downstream watcher/light-client notifications it drives) can be emitted before the SQL transaction that produced the new stability state is guaranteed to have committed, allowing consumers to observe stale state right after being told a unit/MCI is stable.

### Finding Description
`markMcIndexStable()` finishes by emitting stability asynchronously via `process.nextTick`, still inside the same DB transaction/connection that is performing the stabilization writes (balances, `aa_triggers`, data feeds, system votes, etc.): [1](#0-0) 

That transaction is only committed later, back in `writer.js`, after `async.series(arrOps)` (which includes `updateMainChain` → `markMcIndexStable`) finishes and `commit_fn("COMMIT", …)` runs: [2](#0-1) 

The listener for this event in `network.js` explicitly documents the race and applies only a best-effort mitigation: [3](#0-2) 

The comment itself concedes the mitigation is incomplete for one code path: `determineIfStableInLaterUnitsAndUpdateStableMcFlag()` calls back to the caller (releasing/unblocking the original "write" lock context) and *then* continues asynchronously to advance the stability point using a *different* lock (`"handleJoint"`, not `"write"`) and a brand-new DB connection/transaction: [4](#0-3) 

Because `notifyWatchersAboutStableJoints()` only waits on the `"write"` mutex to "make sure [the writing transaction] completes," it provides no synchronization guarantee for stabilizations performed under the `"handleJoint"` lock. In that case, `mci_became_stable` (and the derived `my_transactions_became_stable`, `my_stable-<unit>`, and `light/have_updates` notifications) can reach watchers, wallets, or light clients before the corresponding `COMMIT` for the new stable MCI has actually completed and become visible to other DB readers.

### Impact Explanation
Light clients and local watched-address consumers rely on `mci_became_stable`/`light/have_updates` to know it is safe to fetch/trust newly-stable data (balances, data feed values, AA responses, unit stability status used for payment/AA validation). If a query lands in the tiny window before the underlying transaction is visible, a wallet or AA-triggering flow can act on stale pre-commit data — e.g., mis-reporting an unstable/absent unit as unseen, using outdated data-feed values for an AA response computation, or a light client re-querying and finding the unit still reported as unstable — leading to inconsistent state observed by different parts of the system and potential double-processing or missed dependent triggers. This falls under the "node disagreement on validity or stability" and "data feeds" impact classes referenced by the rules.

### Likelihood Explanation
This is a narrow timing window (rare per the code's own comment: "If the mci became stable in `determineIfStableInLaterUnitsAndUpdateStableMcFlag` (rare)…") that requires a specific catch-up/late-stabilization scenario combined with fast round-trip querying by a watcher or light client immediately following the notification. It is not attacker-controlled in the sense of a directly reachable exploit primitive, but it is a genuine, code-acknowledged race reachable through normal unit posting/stabilization flow (an unprivileged unit poster's units can trigger `determineIfStableInLaterUnitsAndUpdateStableMcFlag`), matching the same root cause class as the referenced Fuel-core report (notify-before-durably-visible).

### Recommendation
Ensure `mci_became_stable` (and any events derived from it) are only emitted after the specific commit that performed the stabilization has fully completed, not merely after the generic `"write"` mutex is free. For the `determineIfStableInLaterUnitsAndUpdateStableMcFlag` path, either emit the stability event only after its own `"handleJoint"`-guarded transaction commits, or have `notifyWatchersAboutStableJoints` wait on the same lock/connection-completion signal used by that path (not just `"write"`), removing the "Hopefully, it'll complete before light/have_updates roundtrip" assumption.

### Proof of Concept
Not directly exploitable via a standalone script; the race is timing-dependent and occurs specifically when stability is advanced via the `determineIfStableInLaterUnitsAndUpdateStableMcFlag` path (late/parent-stability determination) while a watcher/light client races the `mci_became_stable` event with a query against the not-yet-visible commit, as documented in-code at [5](#0-4) .

### Citations

**File:** main_chain.js (L1192-1239)
```javascript
function determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, earlier_unit, arrLaterUnits, bStableInDb, handleResult){
	if (!handleResult)
		return new Promise(resolve => determineIfStableInLaterUnitsAndUpdateStableMcFlag(conn, earlier_unit, arrLaterUnits, bStableInDb, resolve));
	determineIfStableInLaterUnits(conn, earlier_unit, arrLaterUnits, function(bStable){
		console.log("determineIfStableInLaterUnits", earlier_unit, arrLaterUnits, bStable);
		if (!bStable)
			return handleResult(bStable);
		if (bStable && bStableInDb)
			return handleResult(bStable);
		breadcrumbs.add('stable in parents, will wait for handleJoint lock');
		handleResult(bStable, true);

		// result callback already called, we stay here to move the stability point forward.
		// To avoid deadlocks, we always first obtain a "handleJoint" lock, then a db connection
		const bOpListCanChange = hasUnstableOpVoteCount();
		mutex.lock(["handleJoint"], function(unlock){
			breadcrumbs.add('stable in parents, got handleJoint lock');
			storage.readLastStableMcIndex(db, function(last_stable_mci){
				/*if (last_stable_mci >= constants.v4UpgradeMci && !(constants.bTestnet && last_stable_mci === 3547801)) {
					// we don't advance the stability point in v4 as that would necessitate executing triggers and updating actual tps fees. We return a transient error and expect that the stability point will move thanks to other units before the earlier_unit is retransmitted.
					await conn.query("COMMIT");
					conn.release();
					unlock();
					return console.log(`${earlier_unit} not stable in db but stable in later units ${arrLaterUnits.join(', ')} in v4`);
				//	throwError(`${earlier_unit} not stable in db but stable in later units ${arrLaterUnits.join(', ')} in v4`);
				}*/
				storage.readUnitProps(db, earlier_unit, async function(objEarlierUnitProps){
					if (!objEarlierUnitProps.is_on_main_chain)
						throw Error("earlier unit is no longer on main chain");
					var new_last_stable_mci = objEarlierUnitProps.main_chain_index;
					if (new_last_stable_mci <= last_stable_mci || objEarlierUnitProps.is_stable)
						return unlock("the stability point moved while we were waiting for the lock, last_stable_mci="+last_stable_mci+", new_last_stable_mci="+new_last_stable_mci);
					for (let mci = last_stable_mci + 1; mci <= new_last_stable_mci; mci++) {
						if (bOpListCanChange && mci >= constants.v4UpgradeMci) {
							// check stability before every step using the best parent's OP list (the standard rule for advancing stability). The initial stability of the earlier_unit was determined using the OP list of the last stable unit
							const conn = await db.takeConnectionFromPool();
							const [{ unit }] = await conn.query("SELECT unit FROM units WHERE main_chain_index=? AND is_on_main_chain=1", [mci]);
							const bMciStable = await determineIfStableInLaterUnits(conn, unit, arrLaterUnits);
							conn.release();
							if (!bMciStable) break;
						}
						await stabilizeMci(mci);
					}
					unlock();
				});
			});
		});
	});
```

**File:** main_chain.js (L1726-1731)
```javascript
	function finishMarkMcIndexStable() {
			process.nextTick(function(){ // don't call it synchronously with event emitter
				eventBus.emit("mci_became_stable", mci);
			});
			onDone(count_aa_triggers);
	}
```

**File:** writer.js (L699-719)
```javascript
						saveToKvStore(function(){
							profiler.stop('write-batch-write');
							profiler.start();
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
								if (!bInLargerTx)
									conn.release();
								if (!err && !objValidationState.bDryRun){
									eventBus.emit('saved_unit-'+objUnit.unit, objJoint);
									eventBus.emit('saved_unit', objJoint);
								}
```

**File:** network.js (L1785-1793)
```javascript
eventBus.on('mci_became_stable', notifyWatchersAboutStableJoints);

function notifyWatchersAboutStableJoints(mci){
	// the event was emitted from inside mysql transaction, make sure it completes so that the changes are visible
	// If the mci became stable in determineIfStableInLaterUnitsAndUpdateStableMcFlag (rare), write lock is released before the validation commits, 
	// so we might not see this mci as stable yet. Hopefully, it'll complete before light/have_updates roundtrip
	mutex.lock(["write"], function(unlock){
		unlock(); // we don't need to block writes, we requested the lock just to wait that the current write completes
		notifyLocalWatchedAddressesAboutStableJoints(mci);
```
