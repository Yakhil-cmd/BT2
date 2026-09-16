### Title
Unbounded in-memory growth of `assocKnownBadUnits`/`assocKnownBadJoints` caches from unit posting - ([File: joint_storage.js])

### Summary
`joint_storage.js` maintains three module-level JS objects — `assocKnownBadJoints`, `assocKnownBadUnits`, `assocUnhandledUnits` — used as fast-path in-memory caches to avoid re-validating/re-querying units that were already seen. `assocKnownBadUnits` and `assocKnownBadJoints` are populated every time a unit or joint fails validation, but unlike `assocUnhandledUnits` (which is periodically cleaned by `purgeOldUnhandledJoints`), there is no eviction path for the two "known bad" maps. Any unprivileged party that can get an invalid unit processed by the node (by posting a locally-composed unit, or having one relayed) permanently grows this in-memory state, exactly analogous to the go-bitswap `Engine` ledger maps that grew unboundedly per received message and were never cleaned up (GHSA-m974-xj4j-7qv5 / CVE-2023-25568).

### Finding Description
`assocKnownBadUnits` is written in `purgeJointAndDependencies`: [1](#0-0) 

`assocKnownBadJoints` is written in `saveKnownBadJoint`: [2](#0-1) 

Both maps are consulted on every incoming unit/joint via `checkIfNewUnit`/`checkIfNewJoint`: [3](#0-2) 

The only cleanup routine, `purgeOldUnhandledJoints`, only removes entries from `assocUnhandledUnits` (and the corresponding DB rows) for units unhandled for over an hour — it never touches `assocKnownBadUnits` or `assocKnownBadJoints`: [4](#0-3) 

Even the code path that would load persisted bad-joint history at startup is dead code (`return;` before the query), confirming these in-memory maps are treated as ephemeral, unbounded, run-length caches with no size cap: [5](#0-4) 

The entry point that drives this growth is `handleJoint` in `network.js`: any unit/joint that fails `validation.validate`'s `ifUnitError` or `ifJointError` callback results in a new permanent entry keyed by the unit hash or joint hash: [6](#0-5) 

Since unit/joint hashes are derived from arbitrary attacker-controlled content (`objectHash.getUnitHash`/`getJointHash`), an unprivileged unit poster can trivially generate an unbounded stream of syntactically distinct invalid units (e.g., varying the timestamp, a message field, or any other unit content) that each fail validation with a unique hash, adding a new permanent key to `assocKnownBadUnits` or `assocKnownBadJoints`. Because these maps live only in process memory and are never trimmed, this reproduces the "unbounded, persistent memory leak" bug class described in the go-bitswap advisory: attacker-controlled requests each create a small, permanent, never-evicted map entry, and over time the accumulated entries exhaust node memory.

### Impact Explanation
This is an in-memory (not on-disk) unbounded resource consumption bug. Sustained submission of invalid units by a single unprivileged party causes monotonic, unbounded growth of heap memory on any full node, light vendor, or hub that processes the unit through `handleJoint`. Eventually this leads to out-of-memory crashes or severe GC pressure, degrading or halting the node's ability to validate/relay/stabilize legitimate units — a node unable to confirm new units is one of the accepted impact classes for this analysis.

### Likelihood Explanation
High likelihood: the attack requires no special privileges, keys, or coordination — a single actor can locally compose arbitrary invalid units (e.g., bad signatures, malformed fields, wrong hashes) and submit/broadcast them via the normal posting path (`bPosted`/`handleOnlineJoint`/`handleJoint`). Each attempt is cheap to produce (no valid parents, fees or witnessing needed since the unit is rejected at validation) yet still costs the victim node a permanent memory allocation. There is no rate limit or cache eviction mitigating this specifically for `assocKnownBadUnits`/`assocKnownBadJoints`.

### Recommendation
Add bounded eviction (e.g., LRU/TTL, or periodic `Object.keys().length > MAX` reset similar to `storage.js`'s `shrinkCache`) for `assocKnownBadUnits` and `assocKnownBadJoints` in `joint_storage.js`, or cap the number of tracked bad hashes and fall back to the `known_bad_joints`/database check when the cache is full. Consider extending `purgeOldUnhandledJoints` (or a new interval) to also clear stale entries from these two maps, matching the existing pattern already used for `assocUnhandledUnits` and for `storage.js` caches (`shrinkCache`).

### Proof of Concept
1. An unprivileged client crafts N distinct invalid units, e.g. differing only in an unsigned/garbage field or invalid signature, ensuring each has a unique unit hash.
2. Submit them to the node one after another (either as locally posted units or via the P2P `joint` message, both of which converge on `handleJoint` in `network.js`).
3. Each submission triggers `validation.validate`'s `ifUnitError` or `ifJointError` callback, calling `purgeJointAndDependenciesAndNotifyPeers`/`saveKnownBadJoint`, which inserts a new permanent key into `assocKnownBadUnits`/`assocKnownBadJoints` in `joint_storage.js`.
4. Repeating this indefinitely grows the node's heap without bound, since no code path ever deletes these keys, eventually exhausting memory (`joint_storage.js:152-172`, `330-341`, contrasted with the bounded cleanup at `343-355`).

### Citations

**File:** joint_storage.js (L21-51)
```javascript
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
}

function checkIfNewJoint(objJoint, callbacks) {
	checkIfNewUnit(objJoint.unit.unit, {
		ifKnown: callbacks.ifKnown,
		ifKnownUnverified: callbacks.ifKnownUnverified,
		ifKnownBad: callbacks.ifKnownBad,
		ifNew: function(){
			var error = assocKnownBadJoints[objectHash.getJointHash(objJoint)];
			error ? callbacks.ifKnownBad(error) : callbacks.ifNew();
		}
	});
}
```

**File:** joint_storage.js (L152-172)
```javascript
function purgeJointAndDependencies(objJoint, error, onPurgedDependentJoint, onDone){
	var unit = objJoint.unit.unit;
	const truncatedError = truncate(error);
	assocKnownBadUnits[unit] = truncatedError;
	db.takeConnectionFromPool(function(conn){
		var arrQueries = [];
		conn.addQuery(arrQueries, "BEGIN");
		conn.addQuery(arrQueries, "INSERT "+conn.getIgnore()+" INTO known_bad_joints (unit, json, error) VALUES (?,?,?)", [unit, JSON.stringify(objJoint), truncatedError]);
		conn.addQuery(arrQueries, "DELETE FROM unhandled_joints WHERE unit=?", [unit]); // if any
		conn.addQuery(arrQueries, "DELETE FROM dependencies WHERE unit=?", [unit]);
		collectQueriesToPurgeDependentJoints(conn, arrQueries, unit, truncatedError, onPurgedDependentJoint, function(){
			conn.addQuery(arrQueries, "COMMIT");
			async.series(arrQueries, function(){
				delete assocUnhandledUnits[unit];
				conn.release();
				if (onDone)
					onDone();
			})
		});
	});
}
```

**File:** joint_storage.js (L330-341)
```javascript
function saveKnownBadJoint(objJoint, error, onDone){
	var joint_hash = objectHash.getJointHash(objJoint);
	const truncatedError = truncate(error);
	assocKnownBadJoints[joint_hash] = truncatedError;
	db.query(
		"INSERT "+db.getIgnore()+" INTO known_bad_joints (joint, json, error) VALUES (?,?,?)",
		[joint_hash, JSON.stringify(objJoint), truncatedError],
		function(){
			onDone();
		}
	);
}
```

**File:** joint_storage.js (L343-355)
```javascript
function purgeOldUnhandledJoints(){
	db.query("SELECT unit FROM unhandled_joints WHERE creation_date < "+db.addTime("-1 HOUR"), function(rows){
		if (rows.length === 0)
			return;
		var arrUnits = rows.map(function(row){ return row.unit; });
		arrUnits.forEach(function(unit){
			delete assocUnhandledUnits[unit];
		});
		var strUnitsList = arrUnits.map(db.escape).join(', ');
		db.query("DELETE FROM dependencies WHERE unit IN("+strUnitsList+")");
		db.query("DELETE FROM unhandled_joints WHERE unit IN("+strUnitsList+")");
	});
}
```

**File:** joint_storage.js (L357-372)
```javascript
function initUnhandledAndKnownBad(){
	db.query("SELECT unit FROM unhandled_joints", function(rows){
		rows.forEach(function(row){
			assocUnhandledUnits[row.unit] = true;
		});
		return; // ignore old known-bads
		db.query("SELECT unit, joint, error FROM known_bad_joints ORDER BY creation_date DESC LIMIT 1000", function(rows){
			rows.forEach(function(row){
				if (row.unit)
					assocKnownBadUnits[row.unit] = row.error;
				if (row.joint)
					assocKnownBadJoints[row.joint] = row.error;
			});
		});
	});
}
```

**File:** network.js (L1174-1201)
```javascript
			validation.validate(objJoint, {
				ifUnitError: function(error){
					console.log(objJoint.unit.unit+" validation failed: "+error);
					clearHost();
					callbacks.ifUnitError(error);
					if (constants.bDevnet)
						throw Error(error);
					purgeJointAndDependenciesAndNotifyPeers(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					unlock();
					if (ws && error !== 'authentifier verification failed' && !error.match(/bad merkle proof at path/) && !bPosted)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
				},
				ifJointError: function(error){
					clearHost();
					callbacks.ifJointError(error);
				//	throw Error(error);
					joint_storage.saveKnownBadJoint(objJoint, error, function(){
						delete assocUnitsInWork[unit];
					});
					unlock();
					if (ws)
						writeEvent('invalid', ws.host);
					if (objJoint.unsigned)
						eventBus.emit("validated-"+unit, false);
```
