## Title
Data-feed "several values" ambiguity lets a single oracle silently bias the winning value used by default (`ifseveral="last"`) readers - ([File: main_chain.js])

### Summary
`ocore` allows a single oracle address to post multiple, mutually conflicting `data_feed` values for the same `feed_name` in units that all stabilize at the same main-chain index (MCI). Nothing in unit or message validation enforces that an oracle address publish at most one value per `feed_name` per MCI window. When several such conflicting posts exist, any consumer of the feed (an AA's `data_feed[[...]]` formula, or an address-definition `in data feed` condition invoked without an explicit value) that relies on the default resolution mode `ifseveral="last"` silently receives whichever value the storage-write ordering happens to make "win," rather than an explicit, protocol-guaranteed canonical value. This mirrors the reported bug class: multiple coexisting "channels" (here, conflicting feed posts) plus an unnamed/default consumer that implicitly resolves to a single hidden winner.

### Finding Description
`data_feed` message validation only checks feed-name/value length and type constraints; it does not prevent the same oracle address from posting different values for the same `feed_name` in two different units that later stabilize at the same MCI: [1](#0-0) 

When units become stable, `main_chain.js` processes all units sharing an MCI in a fixed but attacker-influenceable order — `ORDER BY level, unit`: [2](#0-1) 

For each unit in that order, `addDataFeeds()` writes both an exact-value index (`df\n...`) and a "latest value" index (`dfv\n...`) keyed only by `address + feed_name + mci`. Because the `dfv` key does not include the unit, a second conflicting post from the same address at the same MCI simply overwrites the first — explicitly acknowledged in the code as "if several values posted on the same mci, the latest one wins": [3](#0-2) 

The winner is therefore whichever unit is processed last in the `ORDER BY level, unit` sequence — an outcome an oracle can bias by choosing unit content/parents to influence its own unit's `level`/hash, without needing peer collusion, node compromise, or any network-timing trick.

On the read side, both the oscript `data_feed[[...]]` formula and the raw `dataFeeds.readDataFeedValueByParams` API default to `ifseveral: 'last'` when the caller does not explicitly request `'abort'`: [4](#0-3) [5](#0-4) 

`readDataFeedByAddress`, which backs this default path, simply keeps overwriting `objResult` whenever a later-MCI-key record turns up, with no signal to the caller that multiple, conflicting values existed for the exact same MCI: [6](#0-5) 

Only callers that explicitly pass `ifseveral: "abort"` detect the ambiguity (`bAbortedBecauseOfSeveral`); this is opt-in, not the default, exactly analogous to Capgo's unnamed `/updates` request silently resolving to a hidden winner channel instead of erroring out on ambiguity.

### Impact Explanation
Any AA or address-definition author who relies on a "trusted" oracle's data feed (e.g., for price data used to compute payout/exchange amounts in an AA, or to gate a spending condition) implicitly assumes at most one value exists per `feed_name` at a given time. An oracle that is authorized to post to that feed (which may be a third-party price reporter, not the AA author) can post two conflicting values in units that both stabilize at the same MCI and steer, via unit-hash/level ordering, which one becomes the resolved value for every default (`ifseveral` unspecified/"last") consumer. This can let the oracle retroactively pick a favorable price/value for itself or a colluding counterparty at AA-execution time, causing AAs to release funds based on a value that was never uniquely "the" feed value at that MCI — i.e., AA fund loss/misallocation driven by protocol-level ambiguity rather than a documented, enforced tie-break the AA author agreed to.

### Likelihood Explanation
No special privilege beyond being a listed/trusted oracle address is required — this is reachable by any address whose data feed an AA or address definition consults, which is a normal, expected role (not a validator, hub, or node operator). Constructing two units with different `data_feed` payloads that both stabilize at the same MCI is straightforward transaction composition; biasing which one sorts later under `ORDER BY level, unit` only requires controlling unit content/parent selection, which the poster already fully controls.

### Recommendation
- Enforce at validation time that a given author address cannot post conflicting values for the same `feed_name` across different units that are candidates for the same MCI (or explicitly document/expose this as a validated, deterministic "first/last by hash" rule visible to formula authors).
- Change the default `ifseveral` behavior (or clearly surface an indicator) so that formula/definition evaluation can distinguish "single canonical value" from "several conflicting values resolved by implementation-defined tie-break," e.g., by making `ifseveral` mandatory or defaulting to `"abort"` for `data_feed` reads without an explicit value filter.
- Consider keying the `dfv` index by unit (not just address+feed_name+mci) and surfacing the conflict count to callers instead of silently overwriting.

### Proof of Concept
1. Oracle address `O` (already used as an oracle in some AA's `data_feed[[oracles="O", feed_name="PRICE", ifseveral="last"]]` expression, the AA-default) constructs two units `U1` and `U2`, both authored by `O`, each carrying a `data_feed` message with `feed_name: "PRICE"` but different values (e.g., `100` and `200`).
2. `O` arranges parents/timing so `U1` and `U2` both become stable at the same MCI `M`, and crafts `U2`'s content so that, per `ORDER BY level, unit` in `main_chain.js`, `U2` is processed after `U1` at MCI `M` (`main_chain.js:1471-1480`).
3. During stabilization, `addDataFeeds()` writes `dfv\nO\nPRICE\n<M>` = `100` when processing `U1`, then overwrites it to `200` when processing `U2` (`main_chain.js:1587-1617`).
4. Any AA that later evaluates `data_feed[[oracles="O", feed_name="PRICE", ifseveral="last"]]` (the default) at MCI ≥ `M` reads `200`, even though the AA author, other data consumers, or observers who saw `U1` first may reasonably have expected `100` to be the value posted "for" MCI `M`. The oracle has retroactively chosen the winning value via unit-ordering, not via an explicit, agreed single canonical post.

### Citations

**File:** validation.js (L1925-1951)
```javascript
		case "data_feed":
			if (objValidationState.bHasDataFeed)
				return callback("can be only one data feed");
			objValidationState.bHasDataFeed = true;
			if (!isNonemptyObject(payload))
				return callback("data feed payload must be non-empty object");
			if (Object.keys(payload).length * objUnit.authors.length > constants.MAX_DATA_FEEDS_PER_MESSAGE)
				return callback("too many data feeds in message");
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
				}
				else if (typeof value === 'number'){
					if (!isInteger(value))
						return callback("fractional numbers not allowed in data feeds");
				}
				else
					return callback("data feed "+feed_name+" must be string or number");
			}
```

**File:** main_chain.js (L1471-1480)
```javascript
	function addBalls(){
		conn.query(
			"SELECT units.*, ball FROM units LEFT JOIN balls USING(unit) \n\
			WHERE main_chain_index=? ORDER BY level, unit", [mci], 
			function(unit_rows){
				if (unit_rows.length === 0)
					throw Error("no units on mci "+mci);
				let voteCountSubjects = [];
				async.eachSeries(
					unit_rows,
```

**File:** main_chain.js (L1587-1617)
```javascript
								function addDataFeeds(payload){
									if (!storage.assocStableUnits[unit])
										throw Error("no stable unit "+unit);
									var arrAuthorAddresses = storage.assocStableUnits[unit].author_addresses;
									if (!arrAuthorAddresses)
										throw Error("no author addresses in "+unit);
									var strMci = string_utils.encodeMci(mci);
									for (var feed_name in payload){
										var value = payload[feed_name];
										var strValue = null;
										var numValue = null;
										if (typeof value === 'string'){
											strValue = value;
											var bLimitedPrecision = (mci < constants.aa2UpgradeMci);
											var float = string_utils.toNumber(value, bLimitedPrecision);
											if (float !== null)
												numValue = string_utils.encodeDoubleInLexicograpicOrder(float);
										}
										else
											numValue = string_utils.encodeDoubleInLexicograpicOrder(value);
										arrAuthorAddresses.forEach(function(address){
											// duplicates will be overwritten, that's ok for data feed search
											if (strValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit);
											if (numValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\nn\n'+numValue+'\n'+strMci, unit);
											// if several values posted on the same mci, the latest one wins
											batch.put('dfv\n'+address+'\n'+feed_name+'\n'+strMci, value+'\n'+unit);
										});
									}
								}
```

**File:** formula/evaluation.js (L620-631)
```javascript
					if (params.min_mci) {
						min_mci = params.min_mci.value.toString();
						if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
							return cb("bad min_mci: "+min_mci);
						min_mci = parseInt(min_mci);
					}
					var ifseveral = 'last';
					if (params.ifseveral){
						ifseveral = params.ifseveral.value;
						if (ifseveral !== 'abort' && ifseveral !== 'last')
							return cb("bad ifseveral: "+ifseveral);
					}
```

**File:** data_feeds.js (L287-330)
```javascript
function readDataFeedByAddress(address, feed_name, value, min_mci, max_mci, ifseveral, objResult, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var bAbortIfSeveral = (ifseveral === 'abort');
	var key_prefix;
	if (value === null){
		key_prefix = 'dfv\n'+address+'\n'+feed_name;
	}
	else{
		var prefixed_value;
		if (typeof value === 'string'){
			var float = string_utils.toNumber(value, bLimitedPrecision);
			if (float !== null)
				prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(float);
			else
				prefixed_value = 's\n'+value;
		}
		else
			prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(value);
		key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value;
	}
	var options = {
		gte: key_prefix+'\n'+string_utils.encodeMci(max_mci),
		lte: key_prefix+'\n'+string_utils.encodeMci(min_mci),
		limit: bAbortIfSeveral ? 2 : 1
	};
	var handleData = function(data){
		if (bAbortIfSeveral && objResult.value !== undefined){
			objResult.bAbortedBecauseOfSeveral = true;
			return;
		}
		var mci = string_utils.getMciFromDataFeedKey(data.key);
		if (objResult.value === undefined || ifseveral === 'last' && mci > objResult.mci){
			if (value !== null){
				objResult.value = string_utils.getValueFromDataFeedKey(data.key);
				objResult.unit = data.value;
			}
			else{
				var arrParts = data.value.split('\n');
				objResult.value = string_utils.getFeedValue(arrParts[0], bLimitedPrecision); // may convert to number
				objResult.unit = arrParts[1];
			}
			objResult.mci = mci;
		}
	};
```

**File:** data_feeds.js (L367-372)
```javascript
	var ifseveral = 'last';
	if ('ifseveral' in params) {
		ifseveral = params.ifseveral;
		if (ifseveral !== 'abort' && ifseveral !== 'last')
			return cb("bad ifseveral: " + util.inspect(ifseveral, { depth: 5 }));
	}
```
