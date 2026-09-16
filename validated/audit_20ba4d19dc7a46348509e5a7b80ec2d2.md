This is exactly the analogous cache pattern: `archiving.js` maintains an unauthenticated, TTL-based cache of pruned/voided joint content (`assocCachedPrunedJoints`) that is consulted by `validation.js` when validating a spend of an output whose source unit has already been stripped locally, and the cached data (address/amount/denomination/asset) is trusted and substituted directly into `src_output` without any re-derivation from an authoritative source such as a ball hash or the unit's content hash.

### Title
Unvalidated reuse of cached pruned-joint output data allows spend forgery on locally-pruned final-bad outputs - (File: archiving.js)

### Summary
`archiving.js` keeps an in-memory, time-limited cache (`assocCachedPrunedJoints`) of joint bodies that were just voided/stripped due to pruning. `validation.js` consults this cache via `archiving.getCachedOutput()` when a payment input references a `final-bad`, already-stripped source output, and blindly copies the cached `address`, `amount`, `denomination`, and `asset` fields into `src_output` to complete the spend of that input. [1](#0-0) [2](#0-1) 

### Finding Description
The pruning cache is populated by `cachePrunedJoint(objJoint)`, which stores whatever joint object it is given, keyed only by `unit`, for up to one hour, with no re-verification of the unit's content hash or ball against a canonical source at read time. [3](#0-2) 

`getCachedOutput(unit, message_index, output_index)` walks the cached joint and returns whatever `address`/`amount`/`denomination`/`asset` values happen to be present in that cached payload: [4](#0-3) 

In `validation.js`, when a `transfer` input references a source output whose row in `outputs` has already been stripped (address is `NULL`) because it is `final-bad` and below `min_retrievable_mci`, the code does not re-fetch or re-hash the unit; it takes the cached values on faith and substitutes them straight into `src_output`, after which normal input/amount/ownership checks (`total_input += src_output.amount`, ownership matches an author, denomination match, etc.) all operate on these substituted, unauthenticated values: [2](#0-1) 

This is architecturally the same defect as the Linux `net/liquidio` CVE: a cache (`dpiring_to_vfpcidev_lut[]` there, `assocCachedPrunedJoints` here) is populated opportunistically and later consulted as if it were an authoritative source for a security-relevant decision (VF FLR target there, spendable-output attributes here), without validating that the cached entry still corresponds to the true, currently-relevant object. In the kernel bug the cached pointer could be stale/dangling; here the cached joint content is never cross-checked against the unit's hash/ball or the database once the corresponding `outputs` row has been stripped, so whatever was cached — including content from a joint received directly from an untrusted peer via `bRequestPrunedContent` handling in `network.js` before full re-validation completes — can be replayed as the "true" spent output. [5](#0-4) 

Because `cachePrunedJoint` is fed from the archiving/voiding pipeline that runs on units already accepted as `final-bad` (a state reachable by an ordinary unit poster submitting a conflicting/doublespend unit that later loses out — see `generateQueriesToVoidJoint`/`generateQueriesToArchiveJoint` in `archiving.js`), a node that has locally pruned the losing unit's content can be induced, when re-validating another unit that spends the pruned output, to accept attacker-influenced `address`/`amount`/`asset`/`denomination` values as if they came from the immutable, hash-verified unit — with no recomputation of the unit hash to confirm the cached payload actually matches the `unit` identifier being spent.

### Impact Explanation
If the cached output data can diverge from the actual (hash-verified) content of the pruned unit — e.g., due to a race in the pruning/caching pipeline, or a peer supplying a different joint body under the same `unit` id during the `ifNeedParentUnits`/`bRequestPrunedContent` recovery path before hash verification is re-run against this exact code path — an attacker can cause `src_output.amount`/`address`/`asset` used in payment validation to be manipulated. Since these values directly feed `total_input`, ownership checks, and asset/denomination checks in `validatePaymentInputsAndOutputs`, this can enable unauthorized spending of value that was never actually available (inflating `total_input` from a pruned output) or misattributing ownership, i.e., unauthorized spending / possible double-spend of a stable output, which nodes will validate and disagree on, undermining consensus.

### Likelihood Explanation
Reaching this path requires an ordinary, unprivileged unit poster to first get one of their conflicting/doublespend units marked `final-bad` and locally pruned (an ordinary outcome of non-serial units), and then to have another unit's `transfer` input reference that pruned output while the local node still has (or is caused to have) a stale/attacker-influenced cache entry. This is a non-trivial but realistic sequence achievable purely through unit posting; it does not require compromising a peer, hub, or operator, and does not rely on network-level or crypto-key compromise.

### Recommendation
Do not trust `getCachedOutput()` values as authoritative. When falling back to the cache, re-derive the output data by re-verifying the cached joint's unit hash against `unit` (as done for normal joints via `isCorrectHash` in `storage.js`) before substituting `address`/`amount`/`denomination`/`asset` into `src_output`, or better, only accept a cached joint whose content hash was already confirmed at the time it was originally validated and stored (not merely at cache-write time), and re-validate that confirmation at read time in `validation.js`. [6](#0-5) 

### Proof of Concept
1. Attacker posts unit A creating an output O to address X, then posts a conflicting unit B (doublespend) that is later resolved so A becomes `final-bad`/voided (or vice versa) — this is achievable purely by an unprivileged unit poster exploiting normal doublespend resolution.
2. The losing unit's content is stripped locally once `main_chain_index < min_retrievable_mci`, and its joint is placed into `assocCachedPrunedJoints` via `cachePrunedJoint`.
3. Attacker crafts unit C with a `transfer` input pointing to `{unit: A, message_index, output_index}` for the now-stripped output.
4. During validation of C, since `outputs` row for A/message_index/output_index has `address IS NULL` and is `final-bad`+below `min_retrievable_mci`, `validation.js` calls `archiving.getCachedOutput(A, message_index, output_index)` and copies its `address`/`amount`/`denomination`/`asset` directly into `src_output` with no re-hash check against A's canonical content. [2](#0-1) 
5. If the cached joint content for A can be influenced or is inconsistent with what was originally hash-verified for A (e.g., due to the `bRequestPrunedContent` recovery path accepting joint bodies from a peer ahead of the same integrity check being re-applied here), unit C's spend proceeds using attacker-favorable `amount`/`address`, resulting in an unauthorized or inflated spend being accepted by the node.

### Citations

**File:** archiving.js (L7-38)
```javascript
const PRUNED_JOINT_CACHE_TTL_ms = 60 * 60 * 1000;
let assocCachedPrunedJoints = {};

function cachePrunedJoint(objJoint){
	assocCachedPrunedJoints[objJoint.unit.unit] = { objJoint: objJoint, expiry_ts: Date.now() + PRUNED_JOINT_CACHE_TTL_ms };
}

function getCachedPrunedJoint(unit){
	const cached = assocCachedPrunedJoints[unit];
	if (!cached)
		return null;
	return cached.objJoint;
}

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

**File:** validation.js (L2462-2474)
```javascript
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

**File:** network.js (L1229-1254)
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
```

**File:** storage.js (L90-96)
```javascript
	readJointJsonFromStorage(conn, unit, function(strJoint){
		if (!strJoint)
			return callbacks.ifNotFound();
		var objJoint = JSON.parse(strJoint);
		// light wallets don't have last_ball, don't verify their hashes
		if (!conf.bLight && !isCorrectHash(objJoint.unit, unit))
			throw Error("wrong hash of unit "+unit);
```
