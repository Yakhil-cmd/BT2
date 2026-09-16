### Title
`in_data_feed[[...]]` inside AA formulas trusts still-unstable, not-yet-finalized data feed posts without checking `sequence`, unlike `data_feed[[...]]` — ([File: data_feeds.js])

### Summary
The Cozy Finance incident worked because the payout trigger accepted an oracle answer that had not yet passed its dispute window, and the attacker who submitted that answer was the same party who benefited from the payout. In ocore, an AA can react to oracle posts before they are final via the "fast path" that scans `storage.assocUnstableMessages` for unstable data-feed units. This fast path exists in two flavors — `data_feed[[...]]` (value read) and `in_data_feed[[...]]` (existence check) — and only the value-read flavor filters out units whose `sequence` is not `'good'`. The existence-check flavor does not, so a not-yet-finalized (and potentially soon-to-be-voided) data feed post can satisfy an AA's condition and trigger an irreversible payment/state change.

### Finding Description
`readDataFeedValue()` explicitly skips any unstable unit whose sequence is not `'good'` before treating its `data_feed` message as valid: [1](#0-0) 

`dataFeedExists()`, used for `in_data_feed[[...]]`, performs the analogous scan over `storage.assocUnstableMessages` but has no such `sequence` check at all: [2](#0-1) 

Both entry points are reachable from AA oscript with `bAA = true`, which is exactly what enables the unstable-message fast path:
- `data_feed[[...]]` calls `dataFeeds.readDataFeedValue(..., bAA, ...)` (protected): [3](#0-2) 
- `in_data_feed[[...]]` calls `dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb)` (unprotected): [4](#0-3) 

By contrast, the address-definition ("smart wallet") flavor of `in data feed` always forces `bAA=false`, so it can never take this unstable-scan shortcut and only ever sees fully stable, KV-store-backed data: [5](#0-4) 

A unit's `sequence` (`good` / `temp-bad` / `final-bad`) is only conclusively resolved at MCI stabilization time, in `handleNonserialUnits()`, based on double-spend conflict detection: [6](#0-5) 

Until that resolution happens, a unit sits in `storage.assocUnstableUnits`/`assocUnstableMessages` with a provisional sequence that can still flip to `final-bad` (i.e., be effectively voided/reversed) once a conflicting double-spend is discovered. `dataFeedExists()`'s bAA fast-path ignores this provisional state entirely and counts the data-feed message as authoritative the moment it is posted and reachable, before its author's unit is proven not to be part of a double-spend.

### Impact Explanation
Any AA whose logic gates a payment or state change on `in_data_feed[[oracles=..., ...]]` can be fed a data-feed post that is still unconfirmed and that the poster (acting as the "oracle"/data source) later voids via a self double-spend, exactly mirroring the Cozy Finance pattern where the same party both supplied the unresolved "YES" answer and reaped the payout before the answer could be disputed/finalized. Because AA responses execute and settle as soon as the *trigger unit's own* MCI stabilizes — independent of whether the *referenced* data-feed unit has itself stabilized — the AA can pay out or update state based on data that never becomes final, causing AA fund loss (unauthorized spending of AA-held balance) or corrupted/incorrect state that cannot be undone. This is a protocol-level oracle-consumption primitive available to any AA author, not an isolated app-level mistake, and it deviates from the safeguard already implemented for the sibling `data_feed[[...]]` value-read path.

### Likelihood Explanation
Exploitation requires the attacker to control the address used as the oracle for the specific `in_data_feed[[...]]` check (i.e., be the data source for that market/condition) and to be able to post a unit that is simultaneously a valid data-feed carrier and a double-spend loser candidate — both of which are ordinary, unprivileged capabilities of any wallet address; no witness, hub, or node compromise is needed. The condition is narrowly timing-dependent (the trigger must land while the data-feed unit is still unstable), but this is a normal, easily engineered race for a single actor who controls both the "oracle" post and the trigger transaction, just as the Cozy Finance attacker controlled both the UMA proposal and the PToken purchase.

### Recommendation
Add the same `sequence !== 'good'` guard used in `readDataFeedValue()` to the bAA fast path in `dataFeedExists()` (`data_feeds.js`, the loop building `bFound` from `storage.assocUnstableMessages`), so that `in_data_feed[[...]]` cannot be satisfied by a unit whose validity is not yet resolved. Alternatively, require `min_mci`/stability guarantees for `in_data_feed` reads used in payout-critical AA branches, and audit all other unstable-message scans in `data_feeds.js` for the same missing check.

### Proof of Concept
1. Deploy an AA whose `if`/`state` formula includes `in_data_feed[[oracles='<ORACLE_ADDR>', feed_name='answer', feed_value='YES']]` gating a payment message (analogous to a PToken/trigger payout).
2. As the controller of `<ORACLE_ADDR>`, craft unit A posting `{app:'data_feed', payload:{answer:'YES'}}`, and simultaneously craft a conflicting unit B that double-spends one of unit A's inputs, broadcasting both so that eventually only one survives stabilization.
3. While unit A is still unstable (present in `storage.assocUnstableMessages`, `sequence` not yet resolved), submit the AA trigger unit. Because `dataFeedExists()`'s bAA path (`data_feeds.js:34-43`) never checks `sequence`, `in_data_feed[[...]]` returns `true` and the AA executes its payout branch.
4. Let unit B win the double-spend race; unit A is marked `final-bad` at stabilization (`main_chain.js` `handleNonserialUnits`). The AA's payment, however, has already been composed and posted in its own unit and is not retroactively reversed, giving the attacker the payout despite the "oracle" answer never having been finalized — mirroring the unauthorized fund extraction seen in the Cozy Finance incident.

### Citations

**File:** data_feeds.js (L34-43)
```javascript
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA)
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
```

**File:** data_feeds.js (L213-224)
```javascript
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA && !bIncludeAllUnstable)
				continue;
			if (objUnit.sequence !== 'good')
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
```

**File:** formula/evaluation.js (L644-656)
```javascript
					if (params.ifnone && !isValidValue(params.ifnone.value))
						return cb("bad ifnone: "+params.ifnone.value);
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
					//	console.log(arrAddresses, feed_name, value, min_mci, ifseveral);
					//	console.log('---- objResult', objResult);
						if (objResult.bAbortedBecauseOfSeveral)
							return cb("several values found");
						if (objResult.value !== undefined){
							if (what === 'unit')
								return cb(null, objResult.unit);
							if (type === 'string')
								return cb(null, objResult.value.toString());
							return cb(null, (typeof objResult.value === 'string') ? objResult.value : createDecimal(objResult.value));
```

**File:** formula/evaluation.js (L738-745)
```javascript
						var min_mci = 0;
						if (evaluated_params.min_mci){
							min_mci = evaluated_params.min_mci.value.toString();
							if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
								return setFatalError('bad min_mci', { arr }, false, cb);
							min_mci = parseInt(min_mci);
						}
						dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb);
```

**File:** definition.js (L933-940)
```javascript
			case 'in data feed':
				// ['in data feed', [['BASE32'], 'data feed name', '=', 'expected value']]
				var arrAddresses = args[0];
				var feed_name = args[1];
				var relation = args[2];
				var value = args[3];
				var min_mci = args[4] || 0;
				dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, objValidationState.last_ball_mci, false, cb2);
```

**File:** main_chain.js (L1318-1362)
```javascript
	function handleNonserialUnits(){
	//	console.log('handleNonserialUnits')
		conn.query(
			"SELECT * FROM units WHERE main_chain_index=? AND sequence!='good' ORDER BY unit", [mci], 
			function(rows){
				var arrFinalBadUnits = [];
				async.eachSeries(
					rows,
					function(row, cb){
						if (row.sequence === 'final-bad'){
							arrFinalBadUnits.push(row.unit);
							return row.content_hash ? cb() : setContentHash(row.unit, cb);
						}
						// temp-bad
						if (row.content_hash)
							throw Error("temp-bad and with content_hash?");
						findStableConflictingUnits(row, function(arrConflictingUnits){
							var sequence = (arrConflictingUnits.length > 0) ? 'final-bad' : 'good';
							console.log("unit "+row.unit+" has competitors "+arrConflictingUnits+", it becomes "+sequence);
							conn.query("UPDATE units SET sequence=? WHERE unit=?", [sequence, row.unit], function(){
								if (sequence === 'good')
									conn.query("UPDATE inputs SET is_unique=1 WHERE unit=?", [row.unit], function(){
										storage.assocStableUnits[row.unit].sequence = 'good';
										cb();
									});
								else{
									arrFinalBadUnits.push(row.unit);
									// treat this unit as a non-existent competitor from now on
									conn.query("UPDATE inputs SET is_unique=NULL WHERE unit=?", [row.unit], function(){
										setContentHash(row.unit, cb);
									});
								}
							});
						});
					},
					function(){
						//if (rows.length > 0)
						//    throw "stop";
						// next op
						arrFinalBadUnits.forEach(function(unit){
							storage.assocStableUnits[unit].sequence = 'final-bad';
						});
						propagateFinalBad(arrFinalBadUnits, addBalls);
					}
				);
```
