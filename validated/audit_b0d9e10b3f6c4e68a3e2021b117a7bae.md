### Title
Use-after-free-style mutation of a shared/cached unit object via `unit[...]` oscript function in AA formulas - ([File: formula/evaluation.js])

### Summary
The `unit` oscript function, reachable from any AA definition or trigger data that an attacker can post, reads a joint via `storage.readJoint` and then mutates the returned `objUnit` object in place (`delete objUnit.actual_tps_fee`, `objectHash.cleanNulls(objUnit)`, deleting `temp_data` payloads) before wrapping it directly (without a `cloneDeep`) into a `wrappedObject` that is exposed to the oscript formula. [1](#0-0) 

### Finding Description
Inside `evaluate()`'s `'unit'` case, when the referenced unit is not the current response unit or a previous-in-batch AA response (i.e. it is read "from the units in the db"), the code calls `storage.readJoint(conn, unit, {...})` and receives `objJoint.unit` as `objUnit`. [2](#0-1) 

Unlike the two other branches of the same function — which explicitly `cloneDeep` the unit object before wrapping it (`new wrappedObject(string_utils.cloneDeep(objResponseUnit))` / `cloneDeep(objPreviousResponseUnit)`) — this third branch mutates `objUnit` directly (`delete objUnit.actual_tps_fee`, `objUnit.timestamp = 0`, `objectHash.cleanNulls(objUnit)`, `delete m.payload.data`) and then wraps the *same, unmodified-by-copy* object reference: `cb(new wrappedObject(objUnit))`. [3](#0-2) 

`storage.js` maintains multiple in-memory unit caches (`assocKnownUnits`, `assocCachedUnits`, `assocUnstableUnits`, `assocStableUnits`, etc.) that are populated once and reused across many subsequent reads/validations for performance. [4](#0-3) 

If `storage.readJoint` (and the underlying `readUnit`/joint cache lookups it calls into) returns a direct reference into one of these long-lived caches rather than a defensive copy, then the in-place mutation performed by the `'unit'` formula handler permanently alters the cached copy of that unit for the life of the process. Every other AA evaluation, getter call, validation pass, or network response (e.g. `light/get_history`, `handleRequest` unit-serving code, or a different AA's own `unit[...]` lookup of the same unit) that subsequently reads the same cached unit object will observe the corrupted/mutated version rather than the pristine original — a stale/aliased-reference bug conceptually equivalent to the DNSdist `getEDNSOptions` use-after-free: a Lua-equivalent (oscript) accessor hands back a live reference into a structure that is expected to be immutable/stable, and a later consumer of the same reference sees data that has been silently altered by an earlier, unrelated invocation.

Because the mutation is content-hash-preserving-looking deletions (`actual_tps_fee`, temp_data payload, null cleanup) driven by "if" conditions gated on `mci`/`bPostPemCurvesFix`/`version`, and because oscript evaluation for AA triggers happens repeatedly and deterministically-expected across all full nodes, any divergence in *when* a given unit object gets first touched by a `unit[...]` call (e.g., depending on whether it is already cached, whether it was already mutated by an earlier AA in the same batch, or by a getter call from a completely different AA address) can cause different nodes — or the same node evaluating the same trigger at different times/cache-states — to compute different results from subsequent formula evaluations, getter calls, or validations that read the same unit.

### Impact Explanation
If nodes' internal caches end up in divergent states (e.g., one node's cache for a given unit has already had `actual_tps_fee`/`temp_data` stripped by a prior AA evaluation while another node's has not, or a node serving light-client history returns an already-mutated unit object), AA evaluation of `unit[...]`-dependent oscript formulas can produce non-deterministic results across nodes. Since AA evaluation results directly determine emitted payments, state changes, and stability of AA response units, this can lead to nodes disagreeing about the validity or content of an AA response unit — a "node disagreement on validity or stability" outcome, and, depending on what formula logic keys off the mutated fields (e.g., a formula branching on `mci`/timestamp/existence of `temp_data`), could enable an attacker-controlled AA (posted by any unprivileged user) to trigger inconsistent AA payouts.

### Likelihood Explanation
Reachability is high: any user can define an AA whose oscript references `unit[<hash>]` and any user can post the triggering unit; no special privileges are required. However, exploitability is uncertain because it depends on whether `storage.readJoint`'s underlying unit-fetch path (`readUnit`/cache lookup functions in `storage.js`) actually returns a **shared, non-cloned reference** from `assocCachedUnits`/`assocUnstableUnits`/`assocStableUnits` — I was not able to fully confirm this within the available tool budget; the grep results show these caches exist and are large-scale reused structures, but I could not trace every code path of `readJoint`/`readUnit` to verify absence of a defensive copy at read time. This is the key uncertainty in this analog.

### Recommendation
Before mutating `objUnit` in the `'unit'` oscript handler, deep-clone it (consistent with the other two branches of the same case that already use `string_utils.cloneDeep`), e.g. wrap with `new wrappedObject(string_utils.cloneDeep(objUnit))` after performing the mutations on the clone, or clone before performing any `delete`/`cleanNulls` mutation. This guarantees oscript execution never mutates objects that may be aliased into long-lived in-memory unit caches, removing any possibility of cross-evaluation or cross-node cache corruption.

### Proof of Concept
Conceptual PoC (exact reproduction requires confirming `readJoint`/cache aliasing, which I could not fully verify):
1. Post/stabilize unit `U` containing a `temp_data` message and/or with a non-null `actual_tps_fee`.
2. Define AA `A` whose oscript formula calls `unit[U].messages` (or similar) — this triggers `storage.readJoint(conn, U, ...)`, causing the handler to `delete m.payload.data` and `cleanNulls` directly on the object returned from `readJoint`.
3. If that returned object is the same reference cached by `storage.js` (`assocCachedUnits`/`assocUnstableUnits`/`assocStableUnits`), a second, unrelated consumer (e.g., a different AA's own `unit[U]` call, a light-client history response, or a later validation step) that reads unit `U` from the same in-memory cache will now observe the already-mutated object (missing `temp_data`, `actual_tps_fee`, or with `timestamp` zeroed), instead of the original persisted content — producing different results than an implementation/node that has not yet cached (or already evicted) that unit.

**Caveat:** I could not conclusively verify, within the tool budget, whether `storage.readJoint`'s underlying data path returns a direct cache reference or an already-copied object; this determination requires reading the full `readJoint`/`readUnit` implementation and the joint-cache population code in `storage.js`, which I was unable to complete before running out of iterations.

### Citations

**File:** formula/evaluation.js (L1573-1616)
```javascript
			case 'unit':
				var unit_expr = arr[1];
				evaluate(unit_expr, function (unit) {
					console.log('---- unit', unit);
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH))
						return cb(false);
					if (bAA) {
						// 1. check the current response unit
						if (objResponseUnit && objResponseUnit.unit === unit)
							return cb(new wrappedObject(string_utils.cloneDeep(objResponseUnit)));
						// 2. check previous response units from the same primary trigger, they are not in the db yet
						for (var i = 0; i < objValidationState.arrPreviousAAResponses.length; i++) {
							var objPreviousResponseUnit = objValidationState.arrPreviousAAResponses[i].unit_obj;
							if (objPreviousResponseUnit && objPreviousResponseUnit.unit === unit)
								return cb(new wrappedObject(string_utils.cloneDeep(objPreviousResponseUnit)));
						}
					}
					// 3. check the units from the db
					console.log('---- reading', unit);
					storage.readJoint(conn, unit, {
						ifNotFound: function () {
							cb(false);
						},
						ifFound: function (objJoint, sequence) {
							console.log('---- found', unit);
							if (sequence !== 'good') // bad units don't exist for us
								return cb(false);
							var objUnit = objJoint.unit;
							if (bPostPemCurvesFix)
								delete objUnit.actual_tps_fee; // might be null in stable units stabilized in the same batch
							if (objUnit.version === constants.versionWithoutTimestamp)
								objUnit.timestamp = 0;
							var unit_mci = objUnit.main_chain_index;
							// ignore units that are not stable or created at a later mci
							if (unit_mci === null || unit_mci > mci)
								return cb(false);
							objectHash.cleanNulls(objUnit); // removes actual_tps_fee which is null in AA responses
							for (let m of objUnit.messages)
								if (m.app === "temp_data")
									delete m.payload.data; // delete temp data if it is not purged yet
							cb(new wrappedObject(objUnit));
						}
```

**File:** storage.js (L29-42)
```javascript
var MAX_ITEMS_IN_CACHE = 300;
var assocKnownUnits = {};
var assocCachedUnits = {};
var assocCachedUnitAuthors = {};
var assocCachedUnitWitnesses = {};
var assocCachedAssetInfos = {};

var assocUnstableUnits = {};
var assocStableUnits = {};
var assocStableUnitsByMci = {};
var assocBestChildren = {};

var assocHashTreeUnitsByBall = {};
var assocUnstableMessages = {};
```
