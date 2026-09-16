### Title
Use of stale "freed" (archived/voided) output data via a time-limited pruned-joint cache lets a crafted last-ball allow spending a final-bad output — ([File: validation.js])

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` is supposed to reject any attempt to spend the output of a unit that is already known to be `final-bad` once that fact is stable relative to the spending unit's `last_ball`. The guard that enforces this (`"spending a stable final-bad output"`) is gated entirely by `bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci)`. An attacker can make this condition false simply by choosing an old `last_ball` for the new unit, even though the referenced input's source unit has long since been archived/voided (its content already stripped and its full body only surviving in a short-lived, per-node cache). This is architecturally analogous to a use-after-free: an object (`final-bad` unit output) that has been logically "freed" (archived, content-stripped, deleted from `outputs`/`units`) is transparently "resurrected" through a stale in-memory cache (`archiving.assocCachedPrunedJoints`, `PRUNED_JOINT_CACHE_TTL_ms` = 1 hour) and fed back into validation as if it were a live, legitimate output.

### Finding Description
`archiving.js` keeps a 1-hour cache of pruned final-bad joints (`assocCachedPrunedJoints`), populated whenever a unit is voided (`storage.js` `updateMinRetrievableMciAfterStabilizingMci` → `archiving.cachePrunedJoint(objJoint)`) or when pruned content is recovered from a peer (`network.js` `tryRecoverPrunedContentOfFinalBadUnit`). [1](#0-0) [2](#0-1) 

In `validation.js`, when validating a `transfer` input whose source output has already been stripped (`!src_output.address`), the code retrieves the "freed" output data straight from this cache via `archiving.getCachedOutput()` and merges it back into `src_output` as if it were authoritative, current data: [3](#0-2) 

Critically, the explicit safeguard against spending a `final-bad` output is only applied `if (bStableInParents)`: [4](#0-3) 

`bStableInParents` depends solely on the *spending unit's own, attacker-chosen* `last_ball_mci` versus the *source* unit's `main_chain_index`. Because a unit author is free to pick an older-than-necessary `last_ball` (there is no freshness/recency requirement on `last_ball` besides monotonicity per-author-chain), an attacker can set `last_ball_mci` below the `main_chain_index` of an already-archived, `final-bad` unit, making `bStableInParents` false and skipping the `"spending a stable final-bad output"` rejection entirely — for every node, pruned or not. On a node that has pruned/voided that source unit, the only reason the flow still succeeds is that the stripped output's data is silently reconstituted from the ephemeral `assocCachedPrunedJoints` cache (or recovered on demand from a peer via `bRequestPrunedContent`), instead of being treated as unavailable/rejected. [5](#0-4) [6](#0-5) 

The subsequent sequence-inheritance logic then just marks the new unit `final-bad` too, but this happens *after* `total_input` has already been credited with the value of an output that should never be spendable (its "true" value was already consumed/never validated as canonical). Because whether this path succeeds or fails depends on each node's independent, time-limited cache state (`PRUNED_JOINT_CACHE_TTL_ms` = 1 hour, populated at different real-world times on different nodes, and also refillable asynchronously from any peer via `get_joint`/`tryRecoverPrunedContentOfFinalBadUnit`), different honest nodes can reach different validation verdicts (`ifOk` vs `ifUnitError`/`unresolved_dependency`) for the exact same posted unit.

### Impact Explanation
This produces node disagreement on unit validity: some nodes (cache hit, or those that fetch the pruned content from the attacker/peer on demand) will accept and save the unit (with inherited `final-bad` sequence), while other nodes (cache miss, TTL expired) will reject it or stall waiting on `bRequestPrunedContent`. Divergent acceptance of a unit that references a phantom (previously-invalidated) output is exactly the "node disagreement on validity or stability" class of impact that is in scope, and it is triggered purely by a single crafted unit from an unprivileged unit poster/AA-adjacent path (ordinary payment unit construction), with no privileged network or hub role required.

### Likelihood Explanation
Reachability requires only: (1) awareness of a recently-voided `final-bad` unit's output (via `archived_joints`/gossip, or by intentionally engineering a double-spend to obtain a losing `final-bad` sibling with known content), and (2) crafting a spending unit with `last_ball_mci` older than that unit's `main_chain_index`. Both are within reach of any ordinary unit-posting party, without cooperation from miners/witnesses/hubs, and the pruned-content-recovery machinery in `network.js` (`ifNeedParentUnits`/`bRequestPrunedContent`) even actively assists an attacker in getting the resurrected output data propagated across the network.

### Recommendation
Make the "spending a stable final-bad/temp-bad output" check independent of the spender's self-chosen `last_ball_mci` when the source unit's badness is already permanently and irrevocably known locally (i.e., once a unit's `sequence` is durably `final-bad`, disallow spending its outputs regardless of `bStableInParents`, rather than only when `bStableInParents` happens to be true). Additionally, `archiving.getCachedOutput()` should not be treated as authoritative validation input for the "is this output spendable" decision — pruned/voided `final-bad` outputs should be permanently rejected for spending purposes rather than reconstructed and revalidated from a transient node-local cache with a fixed, non-consensus-critical TTL.

### Proof of Concept
1. Get (or engineer) a unit `U` that ends up flagged `sequence='final-bad'` on the network (e.g., the losing side of a double-spend), and wait until its `main_chain_index` falls below the target node's `min_retrievable_mci`, so it gets voided/archived (content stripped, `archiving.cachePrunedJoint` populated on that node, or recoverable from peers).
2. Within the pruned-joint cache TTL (or by triggering `bRequestPrunedContent` recovery from a cooperating peer), craft and broadcast a new unit `V` that:
   - Sets `V.last_ball`/`last_ball_mci` to an old, valid stable unit whose `main_chain_index` is lower than `U`'s `main_chain_index` (making `bStableInParents` false in `validation.js`).
   - Includes a `payment` message with a `transfer` input referencing `U`'s stripped output (`input.unit = U`, matching `message_index`/`output_index`), and outputs that balance against `U`'s original output amount.
3. Observe that `validatePaymentInputsAndOutputs()` skips the `"spending a stable final-bad output"` rejection (since `bStableInParents` is false), pulls address/amount from `archiving.getCachedOutput()`, and accepts/saves `V` (inheriting `sequence='final-bad'`) instead of failing outright.
4. Repeat the same broadcast against a peer whose local `assocCachedPrunedJoints` entry for `U` has already expired (TTL elapsed) or was never populated: that node instead returns `unresolved_dependency`/requests recovery, demonstrating divergent acceptance of `V` across the network for the same crafted unit.

### Citations

**File:** archiving.js (L5-5)
```javascript
// in-memory holdover of joints we just voided (stripped final-bad units), so that for a while after pruning
```

**File:** archiving.js (L21-38)
```javascript
// looks up a specific output within a cached pruned joint, in the same shape as the outputs table columns we lost to stripping
function getCachedOutput(unit, message_index, output_index){
	const objJoint = getCachedPrunedJoint(unit);
	if (!objJoint)
		return null;
	const message = objJoint.unit.messages && objJoint.unit.messages[message_index];
	if (!message || message.app !== 'payment' || !message.payload)
		return null;
	const output = message.payload.outputs && message.payload.outputs[output_index];
	if (!output)
		return null;
	return {
		address: output.address,
		amount: output.amount,
		denomination: message.payload.denomination || 1,
		asset: message.payload.asset || null
	};
}
```

**File:** validation.js (L2454-2474)
```javascript
							var src_output = rows[0];
							var bStableInParents = (src_output.main_chain_index !== null && src_output.main_chain_index <= objValidationState.last_ball_mci);
							if (bStableInParents) {
								if (src_output.sequence === 'temp-bad')
									throw Error("spending a stable temp-bad output " + input.unit);
								if (src_output.sequence === 'final-bad')
									return cb("spending a stable final-bad output " + input.unit);
							}
							if (!src_output.address) {
								if (src_output.sequence === 'final-bad' && src_output.main_chain_index < storage.getMinRetrievableMci()) { // already stripped locally
									const objCachedOutput = archiving.getCachedOutput(input.unit, input.message_index, input.output_index);
									if (!objCachedOutput) // ask the peer who sent this unit. If the peer doesn't respond but other nodes have accepted the unit, they'll share it with us, we'll get here again and request input.unit from them
										return cb({error_code: "unresolved_dependency", arrMissingUnits: [input.unit], bRequestPrunedContent: true});
									src_output.address = objCachedOutput.address;
									src_output.amount = objCachedOutput.amount;
									src_output.denomination = objCachedOutput.denomination;
									src_output.asset = objCachedOutput.asset;
								}
								else
									return cb("output being spent " + input.unit + " not found");
							}
```

**File:** validation.js (L2481-2497)
```javascript
							if (bStableInParents && src_output.sequence !== 'good')
								return cb("stable input unit "+input.unit+" is not serial");
							if (objValidationState.last_ball_mci < constants.spendUnconfirmedUpgradeMci){
								if (!objAsset || !objAsset.is_private){
									// for public payments, you can't spend unconfirmed transactions
									if (!bStableInParents)
										return cb("src output must be before last ball");
								}
								if (src_output.sequence !== 'good') // it is also stable or private
									return cb("input unit "+input.unit+" is not serial");
							}
							else{ // after this MCI, spending unconfirmed is allowed for public assets too, non-good sequence will be inherited
								if (src_output.sequence !== 'good'){
									console.log(objUnit.unit + ": inheriting sequence " + src_output.sequence + " from src output " + input.unit);
									if (objValidationState.sequence === 'good' || objValidationState.sequence === 'temp-bad')
										objValidationState.sequence = src_output.sequence;
								}
```

**File:** network.js (L1229-1253)
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
```
