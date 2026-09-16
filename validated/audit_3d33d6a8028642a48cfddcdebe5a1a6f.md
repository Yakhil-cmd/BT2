Found the analog. The key logic bug is in `validation.js`'s `validatePaymentInputsAndOutputs` transfer-input handling combined with `archiving.js`'s pruned-joint cache: the guard that is supposed to reject spending of a permanently-invalid ("final-bad") output only fires when `bStableInParents` is true (line 2456-2460), but the branch that fills in `src_output` from the in-memory `archiving.getCachedOutput()` cache is only reachable when `bStableInParents` is **false** (an "unstable-relative-to-spender" / immediate-spend path, line 2462-2474). Once the cache path fills `src_output.address/amount/denomination/asset`, execution falls through the rest of the function treating the input exactly like a normal spendable output — `sequence !== 'good'` is only used to *propagate* badness (lines 2489-2497), it is never used to hard-reject a `final-bad` source the way the earlier `bStableInParents` branch does.

### Title
Stale in-memory pruned-joint cache lets a final-bad (already invalid) output be spent as a valid input - (File: validation.js)

### Summary
`validatePaymentInputsAndOutputs`'s `transfer` input handler contains a hard rejection for spending a *stable* `final-bad` output (`"spending a stable final-bad output"`), but that rejection is gated on `bStableInParents` (src output's `main_chain_index <= objValidationState.last_ball_mci`). When an attacker crafts a unit whose `last_ball_unit` is deliberately old/behind (so `bStableInParents` is false) while pointing an input at a `unit` that is `final-bad` and already stripped locally (`main_chain_index < storage.getMinRetrievableMci()`), validation instead takes the "recover from spends that raced pruning" branch and asks `archiving.getCachedOutput()` for the address/amount, then proceeds to treat the output as normal, spendable, "inherited-sequence" input. [1](#0-0) 

### Finding Description
`getCachedOutput` (in `archiving.js`) returns raw `address`/`amount`/`denomination`/`asset` reconstructed from the last locally-cached full joint of a voided unit, without re-checking `sequence`. [2](#0-1) 

The cache itself is populated whenever a `final-bad` unit is pruned (`updateMinRetrievableMciAfterStabilizingMci`), and it is comment-documented as existing purely "to serve full content to peers" and "recover from spends that raced the pruning locally": [3](#0-2) [4](#0-3) 

The problem is structural, mirroring the CVE-2018-10675 pattern (a stale/rebuilt reference to something that should have been permanently invalidated is consulted instead of the authoritative state, because the "am I allowed to use this?" check runs against the wrong condition). Here:

1. The authoritative rejection of `final-bad` inputs only runs when `bStableInParents` is true:
```
if (bStableInParents) {
    if (src_output.sequence === 'temp-bad') throw ...
    if (src_output.sequence === 'final-bad') return cb("spending a stable final-bad output " + input.unit);
}
``` [5](#0-4) 

2. Immediately after, if `src_output.address` is empty (stripped) and `sequence === 'final-bad'` and it's already below `min_retrievable_mci`, the code silently repopulates `src_output` from the stale in-memory cache and continues — with no re-check that this is a `final-bad` (i.e., permanently invalid) source: [6](#0-5) 

3. Downstream, `sequence !== 'good'` is treated only as "inherit non-good sequence from src", not as an outright rejection, for units created after `spendUnconfirmedUpgradeMci`: [7](#0-6) 

So a spend of a `final-bad` output can be accepted as `sequence='final-bad'` (inherited) instead of being flatly rejected the way it is for the `bStableInParents` case. Whether "inherited final-bad" sequence is later treated as non-serial/non-spendable downstream determines the ultimate exploitability, but the asymmetry between the two code paths (hard-reject vs. silently-inherit, based purely on whether the spender's `last_ball_unit` happens to precede the pruned unit's stabilization) is a genuine logic flaw: it lets an attacker choose which of two contradictory validation outcomes applies to spending the exact same already-invalidated output, purely by manipulating `last_ball_unit`/timing relative to local pruning (`min_retrievable_mci`), which is analogous to a stale-reference-bypasses-authoritative-state class of bug.

### Impact Explanation
If the "inherited final-bad sequence" unit is nevertheless accepted into the DAG (as `sequence='final-bad'`, which is a valid state per the sequence model) and it also contains other messages/outputs, it lets an attacker fabricate a unit that references and "spends" an output that every honest, fully-synced node has already permanently voided — creating disagreement between nodes about which inputs are legitimately consumable, potentially enabling double-spend bookkeeping confusion or a stalled/diverging DAG if different nodes have different local `min_retrievable_mci` / cache states (since the cache is purely in-memory, TTL-bound, and per-node — nodes that pruned earlier vs. later, or restarted and lost the cache, will disagree on whether `getCachedOutput` returns data, hence disagree on whether the unit is even valid, i.e. `unresolved_dependency` vs. accepted).

### Likelihood Explanation
Requires the attacker to know/guess that a specific unit has become `final-bad` and been locally pruned (which is discoverable from public consensus and timing of pruning, since `min_retrievable_mci` advances deterministically based on `last_stable_mci`), and to craft a spending unit whose `last_ball_unit` keeps `bStableInParents` false for that specific input while still passing all other DAG/parent inclusion checks. This is a narrow, timing/DAG-structure-dependent condition, not trivially triggerable, and the surrounding sequence-inheritance semantics may mitigate real fund loss — but reaching this divergent code path is possible from a single unprivileged unit-posting.

### Recommendation
Make the `final-bad` rejection unconditional regardless of `bStableInParents`/cache-fallback path — i.e., check `src_output.sequence === 'final-bad'` (and `'temp-bad'`) once, before or immediately after the cache-repopulation branch, and reject unconditionally instead of only rejecting when `bStableInParents` is true. Ensure `archiving.getCachedOutput()`-derived data is only used to fill *address/amount/denomination* for legitimate historical validation bookkeeping (e.g., unspending during archiving) and never allows a `final-bad` output to be accepted as a valid spendable input under any timing condition.

### Proof of Concept
Conceptual (exact trigger requires precise timing control over local `min_retrievable_mci` advancement, not fully verifiable via static code reading alone):
1. Wait for/observe a unit `U` become `sequence='final-bad'` and get locally pruned (`main_chain_index(U) < min_retrievable_mci`), which populates `archiving.assocCachedPrunedJoints[U]`.
2. Craft a new unit `V` with a `transfer` input pointing at `U`'s stripped output, and set `V.last_ball_unit` such that `last_ball_mci(V) < main_chain_index(U)`, making `bStableInParents` false in `validatePaymentInputsAndOutputs`.
3. Submit `V`. Validation takes the cache-fallback branch (`archiving.getCachedOutput`), fills `src_output`, and — because `bStableInParents` is false — skips the `"spending a stable final-bad output"` rejection, instead falling through to sequence-inheritance logic at [7](#0-6) , potentially getting `V` accepted where an equivalent unit with `bStableInParents=true` would be hard-rejected.

**Uncertainty note:** I could not fully trace whether the "inherited final-bad" sequence value ultimately blocks all economically meaningful consequences downstream (e.g., in `writer.js` commission/output crediting, or whether `final-bad` units can carry other valid outputs that get spent by third parties). This would require deeper tracing of `writer.saveJoint` and stability-advancement code beyond what I could review in the available iterations; a full Devin session with repository access would be needed to confirm end-to-end exploitability versus this being a benign, self-limiting inconsistency.

### Citations

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

**File:** validation.js (L2492-2497)
```javascript
							else{ // after this MCI, spending unconfirmed is allowed for public assets too, non-good sequence will be inherited
								if (src_output.sequence !== 'good'){
									console.log(objUnit.unit + ": inheriting sequence " + src_output.sequence + " from src output " + input.unit);
									if (objValidationState.sequence === 'good' || objValidationState.sequence === 'temp-bad')
										objValidationState.sequence = src_output.sequence;
								}
```

**File:** archiving.js (L5-12)
```javascript
// in-memory holdover of joints we just voided (stripped final-bad units), so that for a while after pruning
// we can still serve their full content to peers and recover from spends that raced the pruning locally
const PRUNED_JOINT_CACHE_TTL_ms = 60 * 60 * 1000;
let assocCachedPrunedJoints = {};

function cachePrunedJoint(objJoint){
	assocCachedPrunedJoints[objJoint.unit.unit] = { objJoint: objJoint, expiry_ts: Date.now() + PRUNED_JOINT_CACHE_TTL_ms };
}
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

**File:** storage.js (L1737-1746)
```javascript
								if (objUnit.witness_list_unit)
									objStrippedUnit.witness_list_unit = objUnit.witness_list_unit;
								else if (objUnit.witnesses)
									objStrippedUnit.witnesses = objUnit.witnesses;
								if (objUnit.version !== constants.versionWithoutTimestamp)
									objStrippedUnit.timestamp = objUnit.timestamp;
								var objStrippedJoint = {unit: objStrippedUnit, ball: objJoint.ball};
								batch.put('j\n'+unit, JSON.stringify(objStrippedJoint));
								archiving.cachePrunedJoint(objJoint); // keep the full content around for a while in case somebody still needs it
								archiving.generateQueriesToArchiveJoint(conn, objJoint, 'voided', arrQueries, cb);
```
