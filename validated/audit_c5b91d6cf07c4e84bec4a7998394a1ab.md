### Title
Missing `assocUnitsInWork` cleanup in `handleJoint`'s `ifNeedParentUnits` permanently blocks reprocessing of a unit with missing parents - (File: network.js)

### Summary
`network.js`'s `handleJoint()` sets a per-unit in-work flag `assocUnitsInWork[unit] = true` before validating a newly received/posted unit, and every validation-callback branch is responsible for `delete assocUnitsInWork[unit]` once it is done with that unit, analogous to a refcounted resource that must be released on every exit path (mirroring the missing `of_node_put()` in the CVE). In the `ifNeedParentUnits` callback, the flag is deleted only inside the `if (bRequestPrunedContent && !bPosted)` branch; when a unit is missing ordinary (non-pruned) parent units — the common, everyday case for `ifNeedParentUnits` — the flag is never cleared. [1](#0-0) 

### Finding Description
`handleJoint` guards against concurrent/duplicate processing of the same unit hash with an in-memory map: [2](#0-1) 

Every terminal branch of `validation.validate`'s callbacks is expected to release this "lock" by deleting the entry, exactly like a reference count that must be decremented on every return path:
- `ifUnitError`: deletes it inside `purgeJointAndDependenciesAndNotifyPeers`'s callback [3](#0-2) 
- `ifJointError`: deletes it inside `saveKnownBadJoint`'s callback [4](#0-3) 
- `ifTransientError`: deletes it inside `removeUnhandledJointAndDependencies`'s callback [5](#0-4) 
- `ifNeedHashTree`: deletes it directly [6](#0-5) 
- `ifOk` (non-serial branch) and normal success path: deletes/does not need it because the unit becomes known [7](#0-6) 

But `ifNeedParentUnits` only deletes the flag conditionally:

```
ifNeedParentUnits: function(arrMissingUnits, bRequestPrunedContent){
    clearHost();
    if (bRequestPrunedContent && !bPosted) {
        ...
        delete assocUnitsInWork[unit];
        ...
    }
    callbacks.ifNeedParentUnits(arrMissingUnits, bRequestPrunedContent);
    unlock();
},
``` [1](#0-0) 

`bRequestPrunedContent` is only truthy in the specific "locally pruned final-bad output" scenario. In the ordinary case — any unit whose parents are simply not yet known to this node (a completely normal, attacker-reachable condition: anyone can post a unit referencing parents the node hasn't received yet) — this condition is false, and `assocUnitsInWork[unit]` is left set to `true` forever (until process restart), even though the unit's own validation attempt has fully finished and `unlock()` on the `handleJoint` mutex has been called.

### Impact Explanation
Because the flag is never cleared for a "missing parents" unit, any subsequent delivery of that exact same unit (retransmission from a peer, resubmission after parents finally arrive, e.g. via `network.requestJoints`/catch-up flow, or a client re-posting) is silently rejected at the earliest check: [2](#0-1) 

`callbacks.ifUnitInWork()` is invoked and the unit is never (re-)validated or saved by this node, even after its parents become fully available. This is a node-local availability/consistency bug: the affected node becomes permanently unable to accept and confirm that specific unit (and, if that unit is a needed parent for other units, transitively blocks progress on units depending on it), producing a node that disagrees with the rest of the network about whether valid units can be included/confirmed — matching the "network unable to confirm new units" impact category. Any unprivileged peer or unit poster can trigger this simply by broadcasting a unit that references not-yet-known parents, which is an ordinary and frequent event in a DAG ledger (not a "malicious peer/p2p/DoS-only" special case — it's normal traffic).

### Likelihood Explanation
High reachability, low complexity: `ifNeedParentUnits` fires routinely whenever a broadcast unit's parents are not yet locally known — this happens naturally during normal network operation and can be trivially and repeatably triggered by any unit poster referencing missing parents without ever setting `bRequestPrunedContent`. No special privileges, timing races, or malicious infrastructure are required.

### Recommendation
Unconditionally clear the in-work flag in the `ifNeedParentUnits` callback (moving `delete assocUnitsInWork[unit];` outside the `if (bRequestPrunedContent && !bPosted)` block), mirroring the pattern already used by the other terminal callbacks (`ifUnitError`, `ifJointError`, `ifTransientError`, `ifNeedHashTree`), so the unit can be re-validated once its parents are later obtained.

### Proof of Concept
1. Craft/broadcast a valid unit `U` whose `parent_units` reference at least one unit `P` that the target node does not have.
2. The target node calls `handleJoint(ws, jointU, ...)`; `assocUnitsInWork[U] = true` is set, validation proceeds and hits `ifNeedParentUnits` with `bRequestPrunedContent` falsy (ordinary missing-parent case) — the flag for `U` is never deleted.
3. Later, resend unit `U` (or let it arrive again through normal gossip/catch-up after `P` has been obtained) to the same node.
4. `handleJoint` immediately short-circuits at `if (assocUnitsInWork[unit]) return callbacks.ifUnitInWork();` — the node refuses to (re)validate/save `U`, permanently, until process restart, even though `U` is fully valid and its parents are now available.

### Citations

**File:** network.js (L1161-1163)
```javascript
	if (assocUnitsInWork[unit])
		return callbacks.ifUnitInWork();
	assocUnitsInWork[unit] = true;
```

**File:** network.js (L1181-1183)
```javascript
					purgeJointAndDependenciesAndNotifyPeers(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
```

**File:** network.js (L1194-1196)
```javascript
					joint_storage.saveKnownBadJoint(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
```

**File:** network.js (L1209-1213)
```javascript
					joint_storage.removeUnhandledJointAndDependencies(unit, function(){
					//	if (objJoint.ball)
					//		db.query("DELETE FROM hash_tree_balls WHERE ball=? AND unit=?", [objJoint.ball, objJoint.unit.unit]);
						delete assocUnitsInWork[unit];
					});
```

**File:** network.js (L1224-1227)
```javascript
					callbacks.ifNeedHashTree();
					// we are not saving unhandled joint because we don't know dependencies
					delete assocUnitsInWork[unit];
					unlock();
```

**File:** network.js (L1229-1256)
```javascript
				ifNeedParentUnits: function(arrMissingUnits, bRequestPrunedContent){
					clearHost();
					if (bRequestPrunedContent && !bPosted) {
						// e.g. spending a locally pruned final-bad output: hold on to this joint ourselves and retry it if/when we
						// recover the missing content, since the missing unit already has a row in the units table and the usual
						// dependencies table would (wrongly) consider it satisfied right away.
						// the joint body goes to rocksdb (see comment on assocUnitsWaitingForPrunedContent), keyed by its own unit
						kvstore.put('wj\n' + unit, JSON.stringify({ objJoint, peer: ws ? ws.peer : null }), () => {});
						const expiry_ts = Date.now() + 60 * 60 * 1000;
						for (let missing_unit of arrMissingUnits) {
							if (!assocUnitsWaitingForPrunedContent[missing_unit])
								assocUnitsWaitingForPrunedContent[missing_unit] = [];
							assocUnitsWaitingForPrunedContent[missing_unit].push({ unit, expiry_ts });
						}
						delete assocUnitsInWork[unit];
						// requestNewMissingJoints relies on checkIfNewUnit, which can say ifKnown() for a unit that only has
						// stale props cached in assocCachedUnits, even though its full content is exactly what we are missing
						// Also, don't check havePendingJointRequest as the peer of an earlier request could intentionally withhold the unit (there is rerouting, but it would give up at the first peer that doesn't have the unit)
						// ws can be null here (e.g. replaying a saved joint whose original sender already disconnected)
						if (ws)
							requestJoints(ws, arrMissingUnits);
						else
							findNextPeer(null, function(next_ws){
								requestJoints(next_ws, arrMissingUnits);
							});
					}
					callbacks.ifNeedParentUnits(arrMissingUnits, bRequestPrunedContent);
					unlock();
```

**File:** network.js (L1262-1266)
```javascript
					if (bPosted && objValidationState.sequence !== 'good') {
						validation_unlock();
						callbacks.ifUnitError("The transaction would be non-serial (a double spend)");
						delete assocUnitsInWork[unit];
						unlock();
```
