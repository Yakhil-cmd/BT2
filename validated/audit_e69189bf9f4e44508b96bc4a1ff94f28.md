## Title
Unit identity hash (`getUnitHash`) excludes author signatures/definitions, allowing a poisoned "known-bad" cache entry to permanently block a legitimately signed unit - ([File: object_hash.js])

### Summary
The CVE describes Zebra caching "verified" status keyed by a `txid` that, per ZIP-244, deliberately excludes the *Authorization Data* (signatures/proofs), so a miner could substitute a differently-signed transaction under the same `txid` and have signature verification skipped. Ocore has an analogous identity/cache-key weakness: the `unit` hash that is used everywhere as the primary key, dedupe key, and "already validated / already known-bad" cache key is computed from a stripped representation of the unit that keeps only each author's `address`, discarding `definition` and `authentifiers` (the actual signatures).

### Finding Description
`getUnitHash()` computes the unit's identity hash from `getStrippedUnit()`: [1](#0-0) 

Note that `objStrippedUnit.authors` is built as `objUnit.authors.map(author => ({address: author.address}))` — i.e. `definition` and `authentifiers` (the cryptographic signature material) are never part of the value hashed into `unit`. This is architecturally identical to ZIP-244's txid design: the identity/cache key is computed over content that excludes authorization data.

This `unit` value is then used as the sole key for a battery of "already known" caches that skip re-validation entirely: [2](#0-1) 

`assocKnownBadUnits` and `storage.isKnownUnit()` (backed by `assocKnownUnits`) short-circuit the pipeline via `ifKnownBad()` / `ifKnown()` in `handleJoint`, without ever calling `validateAuthors()` again: [3](#0-2) 

Because `unit` does not depend on `authentifiers`/`definition`, an attacker who observes (or predicts) a pending unit's content (parents, messages, headers/payload commissions, timestamp, addresses) can construct a variant with the *same* `unit` hash but garbage/invalid `authentifiers`. If this poisoned variant reaches a node first, `validateAuthors()` in `validation.js` will fail (bad signature), and the node will record the *unit hash* itself in `assocKnownBadUnits` (via the `ifUnitError`/`ifKnownBad` path in `network.js`'s `handleJoint`). Because the cache key is content-derived but signature-independent, the subsequently broadcast, legitimately-signed unit with the identical `unit` value will be intercepted by `checkIfNewUnit()`'s `assocKnownBadUnits[unit]` check and rejected via `ifKnownBad()` — without ever re-attempting real signature verification, exactly mirroring the CVE's root cause: an identity/cache key that excludes authorization data causes the node to substitute a decision made on the wrong (or no) authorization data for the one that should apply to the newly-seen content.

### Impact Explanation
This lets any unprivileged network participant who can observe/predict an about-to-be-broadcast unit (e.g., by watching mempool gossip or by racing a wallet's own broadcast) permanently poison that specific `unit` id as "known bad" on any node the forged variant reaches first. The legitimately signed transaction with the same `unit` hash is then unconditionally rejected on those nodes forever (or until cache eviction/restart), producing a persistent denial of confirmation for a specific victim payment/AA trigger — i.e., "a network unable to confirm new units" for that content, and potential node-to-node disagreement about validity depending on propagation race outcomes across the network (nodes that saw the legitimate copy first accept it; nodes poisoned first permanently reject it).

### Likelihood Explanation
Exploitation requires no privileged position — only the ability to send a `joint`/`justsaying` message to a target node before the legitimate, correctly-signed unit arrives, and knowledge of the unit's non-authorization content (achievable by observing gossip, or by an on-path/first-hop relay). Constructing the colliding `unit` hash is trivial since it requires no cryptographic work — only reproducing the address (public information) while supplying arbitrary bytes for `authentifiers`.

### Recommendation
Tie negative/positive "known" caching decisions to authorization-bound data, not solely to the signature-independent `unit` hash. Specifically:
- Do not cache "known-bad" status by `unit` alone when the failure is a signature/authorization error; distinguish transient/content-independent errors from ones that depend on the specific authentifiers/definition supplied, or key such caches off a hash that includes authors' `definition`/`authentifiers`.
- When `ifKnownBad()`/`ifKnown()` short-circuits are hit, ensure they cannot suppress delivery of a differently-authorized but otherwise identical unit — e.g., re-validate authors whenever the incoming joint's authentifiers/definition differ from what was cached, rather than trusting the stripped `unit` id alone.

### Proof of Concept
1. Observe a not-yet-confirmed unit `U` (from mempool gossip or a wallet's own pre-broadcast) with `unit = objectHash.getUnitHash(U)`, whose value is computed only from `{content_hash-relevant fields, authors:[{address}], parent_units, ...}` per `getStrippedUnit()` — see [4](#0-3) .
2. Craft `U'` = deep copy of `U`'s JSON, but replace `authors[i].authentifiers` with garbage strings (or an unrelated bogus `definition` if none is cached yet). Because `getUnitHash` never includes `authentifiers`/`definition`, `objectHash.getUnitHash(U') === objectHash.getUnitHash(U) === unit`.
3. Broadcast `U'` to a target node before `U` arrives. `validateAuthors()` fails signature verification; the node's `handleJoint` `ifUnitError` path stores `assocKnownBadUnits[unit] = error` (per `joint_storage.js`'s design, see [5](#0-4) ).
4. When the legitimate `U` later arrives at that node, `joint_storage.checkIfNewJoint`/`checkIfNewUnit` finds `assocKnownBadUnits[unit]` already populated and calls `ifKnownBad()`, permanently rejecting the valid, correctly-signed unit — see [3](#0-2) .

Note: I was not able to fully trace every downstream consumer of `assocKnownBadUnits`/`isKnownUnit` (e.g., cache eviction timing, `shrinkCache()` interactions in `storage.js`) within the available search budget, so the exact persistence window of the poisoned "known-bad" state should be verified with a live/instrumented test rather than static reading alone.

### Citations

**File:** object_hash.js (L60-87)
```javascript
function getUnitHash(objUnit) {
	var bVersion2 = (objUnit.version !== constants.versionWithoutTimestamp);
	if (objUnit.content_hash) // already stripped and objUnit doesn't have messages
		return getBase64Hash(getNakedUnit(objUnit), bVersion2);
	return getBase64Hash(getStrippedUnit(objUnit), bVersion2);
}

function getStrippedUnit(objUnit) {
	var bVersion2 = (objUnit.version !== constants.versionWithoutTimestamp);
	var objStrippedUnit = {
		content_hash: getUnitContentHash(objUnit),
		version: objUnit.version,
		alt: objUnit.alt,
		authors: objUnit.authors.map(function(author){ return {address: author.address}; }) // already sorted
	};
	if (objUnit.witness_list_unit)
		objStrippedUnit.witness_list_unit = objUnit.witness_list_unit;
	else if (objUnit.witnesses)
		objStrippedUnit.witnesses = objUnit.witnesses;
	if (objUnit.parent_units){
		objStrippedUnit.parent_units = objUnit.parent_units;
		objStrippedUnit.last_ball = objUnit.last_ball;
		objStrippedUnit.last_ball_unit = objUnit.last_ball_unit;
	}
	if (bVersion2)
		objStrippedUnit.timestamp = objUnit.timestamp;
	return objStrippedUnit;
}
```

**File:** joint_storage.js (L16-38)
```javascript
var assocKnownBadJoints = {};
var assocKnownBadUnits = {};
var assocUnhandledUnits = {};


function checkIfNewUnit(unit, callbacks) {
	if (storage.isKnownUnit(unit))
		return callbacks.ifKnown();
	if (assocUnhandledUnits[unit])
		return callbacks.ifKnownUnverified();
	var error = assocKnownBadUnits[unit];
	if (error)
		return callbacks.ifKnownBad(error);
	db.query("SELECT sequence, main_chain_index FROM units WHERE unit=?", [unit], function(rows){
		if (rows.length > 0){
			var row = rows[0];
			if (row.sequence === 'final-bad' && row.main_chain_index !== null && row.main_chain_index < storage.getMinRetrievableMci()) // already stripped
				return callbacks.ifNew();
			storage.setUnitIsKnown(unit);
			return callbacks.ifKnown();
		}
		callbacks.ifNew();
	});
```

**File:** network.js (L1308-1323)
```javascript
	joint_storage.checkIfNewJoint(objJoint, {
		ifNew: function(){
			bSaved ? callbacks.ifNew() : validate();
		},
		ifKnown: function(){
			callbacks.ifKnown();
			delete assocUnitsInWork[unit];
		},
		ifKnownBad: function(){
			callbacks.ifKnownBad();
			delete assocUnitsInWork[unit];
		},
		ifKnownUnverified: function(){
			bSaved ? validate() : callbacks.ifKnownUnverified();
		}
	});
```
