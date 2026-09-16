### Title
Stale unlocked read of `hasUnstableOpVoteCount()` used to decide OP-list-aware re-stabilization checks - ([File: main_chain.js])

### Summary
`determineIfStableInLaterUnitsAndUpdateStableMcFlag()` in [1](#0-0)  reads the shared, mutable flag `hasUnstableOpVoteCount()` *before* acquiring the `handleJoint` mutex lock, then uses that stale boolean deep inside the locked/critical section to decide whether every advancing MCI must be re-checked for stability against the best parent's (potentially changed) OP list.

### Finding Description
The bug-class analog to CVE-2024-36922 is "read a shared/volatile piece of state without the lock that protects it, then use the stale value once the lock is finally obtained, allowing the state to have changed out from under the check." In iwlwifi, `txq->read_ptr` was read outside the lock and then used to reclaim TX queue entries, causing a double reclaim once two callers raced. In ocore, the analogous pattern is:

```js
const bOpListCanChange = hasUnstableOpVoteCount();   // <- read WITHOUT lock
mutex.lock(["handleJoint"], function(unlock){        // <- lock acquired afterwards
    ...
    for (let mci = last_stable_mci + 1; mci <= new_last_stable_mci; mci++) {
        if (bOpListCanChange && mci >= constants.v4UpgradeMci) {
            // check stability against best parent's OP list only if the pre-lock read said so
            ...
        }
        await stabilizeMci(mci);
    }
    unlock();
});
``` [2](#0-1) 

`hasUnstableOpVoteCount()` itself just scans `storage.assocUnstableMessages` for an in-flight `system_vote_count`/`op_list` message and returns a boolean [3](#0-2) . Because this scan happens *before* `mutex.lock(["handleJoint"], ...)` is granted, and lock acquisition can be arbitrarily delayed while other joints are being validated/written (each of which can insert or remove entries from `assocUnstableMessages`, e.g. via `writer.js` adding an unstable `system_vote_count` message at line [4](#0-3) , or `main_chain.js`'s `markMcIndexStable` deleting `assocUnstableMessages[unit]` once a unit stabilizes [5](#0-4) ), the value of `bOpListCanChange` captured before the lock can be out of date by the time the loop over `[last_stable_mci+1 .. new_last_stable_mci]` actually runs inside the lock.

Two failure directions follow directly from this stale read:
- **False negative (`bOpListCanChange = false` although a vote just became unstable)**: the loop skips the extra `determineIfStableInLaterUnits` re-check per MCI that the comment says is "the standard rule for advancing stability" when the OP list can change, and instead stabilizes the MCI unconditionally via `stabilizeMci(mci)`. If the OP list actually changes at that MCI (because the vote became unstable milliseconds after the pre-lock check), this node advances stability using outdated witnessing/OP-list assumptions that a strictly-correct implementation would have rejected or deferred.
- **False positive (`bOpListCanChange = true` although the vote count already got counted/removed before the lock was granted)**: unnecessary but harmless extra re-checks (less severe direction), though it still demonstrates the check is not atomic with the state it inspects.

The first direction is the concerning one: nodes that happen to acquire the `handleJoint` lock at slightly different times relative to when a `system_vote_count` message enters/leaves `assocUnstableMessages` can end up with different values of `bOpListCanChange` for the very same MCI range, causing them to run different code paths (extra per-MCI OP-list-based stability re-verification vs. none) while stabilizing main-chain indexes. Because the main chain and OP list are core to consensus validity (an MCI's stability and the identity of witnesses/OPs governing its transactions), two honest full nodes reaching a different conclusion about whether unit X at MCI Y is stable creates a **node disagreement on validity/stability** — the exact type of impact this scan is required to find, and structurally the same "TOCTOU on state that changes concurrently with the state actually being protected by the lock" defect as the reported CVE.

### Impact Explanation
If nodes disagree on the sequence of OP-list-aware re-validation performed while marking MC indexes stable, they can diverge on which units are considered stable/good at a given MCI, especially around OP-list vote transitions. This is a stability/consensus-divergence risk: units, AA trigger executions, and TPS-fee accounting downstream of `stabilizeMci()` all depend on identical, deterministic evaluation of `bOpListCanChange` across all nodes. A divergence here can propagate into differing ledger states across the network (double-spend acceptance divergence, inconsistent AA execution, or a stuck/forked stability point), i.e. exactly the "node disagreement on validity or stability" outcome called out as an acceptable impact category.

### Likelihood Explanation
Triggering this requires only ordinary network activity: any address (reachable by any unprivileged unit poster) can submit a `system_vote` for `op_list` (a normal, permissionless `oscript`/message type validated in [6](#0-5) ), and its presence/absence in `storage.assocUnstableMessages` is what flips `hasUnstableOpVoteCount()`. Because `mutex.lock(["handleJoint"], ...)` can be queued behind other in-flight joint validations (a normal, frequent occurrence under load), the window between the pre-lock read and the lock's actual grant is not negligible, especially on busy or catching-up nodes. No privileged access, timing attack against cryptography, or malicious peer/hub is required — just ordinary posting of an `op_list` system vote unit concurrently with unrelated unit processing.

### Recommendation
Move the `hasUnstableOpVoteCount()` evaluation to *inside* the `mutex.lock(["handleJoint"], ...)` callback, immediately before it's used in the `for` loop, so the read of `storage.assocUnstableMessages` and its use to decide the per-MCI stability-recheck behavior are atomic with respect to the lock that protects concurrent mutation of that map (mirroring the upstream iwlwifi fix of moving `read_ptr` access under the lock that guards it).

### Proof of Concept
Not concretely reproducible from static analysis alone (requires precise timing across two nodes and manipulation of validation-queue backlog to widen the pre-lock/lock-acquisition window); this report is based on structural code-path analysis rather than a runnable exploit. A conceptual PoC:
1. Node A begins a heavy backlog of unit validations, so any subsequent `mutex.lock(["handleJoint"], ...)` call queues for a noticeable interval.
2. An attacker posts a unit containing a `system_vote_count` message for `op_list` that is included as a stable-in-parents unit right as another call to `determineIfStableInLaterUnitsAndUpdateStableMcFlag` performs its pre-lock `hasUnstableOpVoteCount()` check (returns `false`).
3. Before the queued `mutex.lock(["handleJoint"], ...)` callback actually runs, the vote-count unit is processed and inserted into `storage.assocUnstableMessages` (making the OP list "in flux").
4. The stabilization loop proceeds with `bOpListCanChange=false`, skipping the extra per-MCI OP-list stability re-check, while a peer node whose lock acquisition raced differently sets `bOpListCanChange=true` and performs the extra check — producing a stability/validity divergence between the two nodes for the same MCI range.

### Citations

**File:** main_chain.js (L1192-1240)
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
}
```

**File:** main_chain.js (L1243-1251)
```javascript
function hasUnstableOpVoteCount() {
	for (let unit in storage.assocUnstableMessages) {
		for (let message of storage.assocUnstableMessages[unit]) {
			if (message.app === 'system_vote_count' && message.payload === 'op_list')
				return true;
		}
	}
	return false;
}
```

**File:** main_chain.js (L1575-1584)
```javascript
											case 'system_vote_count': // will be processed later, when we finish this mci
												if (!voteCountSubjects.includes(payload))
													voteCountSubjects.push(payload);
												break;
											default:
												throw Error("unrecognized app in unstable message: " + app);
										}
									}
									delete storage.assocUnstableMessages[unit];
									cb();
```

**File:** writer.js (L603-612)
```javascript
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
```

**File:** validation.js (L1860-1883)
```javascript
			switch (payload.subject) {
				case "op_list":
					const arrOPs = payload.value;
					if (!isArrayOfLength(arrOPs, constants.COUNT_WITNESSES))
						return callback("OP list must be an array of " + constants.COUNT_WITNESSES);
					if (!arrOPs.every(isValidAddress))
						return callback("all OPs must be valid addresses");
					let prev_op = arrOPs[0];
					for (let i = 1; i < arrOPs.length; i++){
						const op = arrOPs[i];
						if (op <= prev_op)
							return callback("OP list must be sorted and unique");
						prev_op = op;
					}
					checkNotAAs(conn, arrOPs, objValidationState.last_ball_mci, err => {
						if (err)
							return callback(err);
						checkWitnessesKnownAndGood(conn, objValidationState, arrOPs, err => {
							if (err)
								return callback(err);
							checkNoReferencesInWitnessAddressDefinitions(conn, objValidationState, arrOPs, callback);
						});
					});
					break;
```
