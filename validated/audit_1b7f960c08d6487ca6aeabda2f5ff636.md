Based on the code I've examined, the closest reachable analog to the Curve `get_dy()` "wrong interface" bug class in `ocore` is the dual, non-equivalent implementations of the oracle "value-matches" predicate used by `in_data_feed`/`in data feed` (address-definition and AA-formula oracle lookups). One implementation ("fast path" over still-unstable messages) and the other (canonical, persisted key-value lookup) encode/compare values through different "interfaces," and they can disagree for the exact same conceptual comparison.

### Title
Inconsistent value-equality interfaces between the unstable-message fast path and the persisted KV-store lookup in `in_data_feed`/`in data feed` allow oracle-value mismatches that AA logic cannot safely rely on - (File: `data_feeds.js`)

### Summary
`data_feeds.js` implements the oracle lookup used by the oscript operators `data_feed`, `in_data_feed` (AA formulas) and `in data feed` (address-definition authentifiers) through **two different comparison "interfaces"** for the very same logical operation ("does oracle X's feed named Y satisfy relation R against value V?"):
- a JS-native, type-coercing comparison over still-unstable AA messages held in memory (`dataFeedExists`, the `bAA` branch), and
- a canonical, format-normalizing lookup against the persisted key-value store (`dataFeedByAddressExists`), which is the representation actually written to disk once a unit stabilizes.

These two interfaces do not always agree on whether a given feed value matches the requested value, exactly the same class of defect as the reported Curve issue: assuming one function "interface" is equivalent to another without verifying the equivalence for all valid inputs.

### Finding Description
`dataFeedExists()` in `data_feeds.js` has a fast in-memory path over `storage.assocUnstableMessages`, used only `if (bAA)` (i.e., when evaluating inside AA/oscript logic): [1](#0-0) 

For the `=` relation, this path performs a **raw, non-numeric-normalizing** comparison:
```
if (relation === '=') {
    if (value === feed_value || value.toString() === feed_value.toString())
        bFound = true;
    return;
}
``` [2](#0-1) 

By contrast, the persisted/canonical path, `dataFeedByAddressExists()`, normalizes the requested value using `string_utils.toNumber()` and encodes it with `encodeDoubleInLexicograpicOrder()` before constructing the key prefix used to search the KV store: [3](#0-2) 

The same normalization (`toNumber` → `encodeDoubleInLexicograpicOrder`) is what is actually written to disk for every data feed value once its unit stabilizes, in `main_chain.js`'s `addDataFeeds()`: [4](#0-3) 

Because the fast (unstable) path uses `.toString()` equality while the persisted path uses numeric-value equality via lexicographic float encoding, two representations of the *same number* (e.g. `5`, `"5.0"`, `"05"`, `"5e0"`) that the persisted interface treats as equal are **not** treated as equal by the in-memory fast path, and vice versa for values that only coincidentally stringify the same. This means the "does the oracle feed equal V" predicate used by `in_data_feed` can return different answers for the identical underlying oracle value depending on which of the two "interfaces" ends up answering the query — i.e., on whether the oracle's data-feed-posting unit is still unstable at the moment the predicate is evaluated versus already stabilized (`data_feedExists` falls back to `dataFeedByAddressExists` in all cases, but the unstable fast path can short-circuit to `true`/return before that persisted check runs — see the `if (bFound) return handleResult(true);` short-circuit): [5](#0-4) 

This is directly analogous to the reported Curve bug: the code silently assumes a single "interface" (comparison semantics) is universally correct, when in fact a second, differently-behaving interface exists and is reachable for the same conceptual operation, producing wrong results for legitimate inputs it wasn't designed to expect.

### Impact Explanation
AA authors write `in_data_feed(oracle, feed_name, '=', V)` expecting deterministic, format-independent equality with the value an oracle posted. Because the equality semantics silently differ between the unstable/in-memory interface and the persisted/canonical interface, an oracle (or anyone able to influence how a numeric value is stringified in a `data_feed` message payload, e.g. `"5.0"` vs `5` vs `"5e0"`) can cause `in_data_feed` conditions guarding fund release, price triggers, or state transitions in an AA to be satisfied (or not satisfied) in a way the AA author did not intend, purely as an artifact of the number's textual representation rather than its numeric value. This can lead to AA funds being released under conditions the AA logic intended to reject, or legitimate releases being blocked (AA fund loss/freezing).

### Likelihood Explanation
Exploitation requires an oracle-controlled or oracle-influenced `data_feed` payload with a numeric value expressed in a non-canonical string form (e.g., `"5.0"` instead of `5`), combined with an AA formula that relies on `in_data_feed(...,'=',...)` for authorization/logic gating while that specific unit is still unstable when the AA trigger executes. Given that data feeds are commonly numeric price/oracle values posted as strings and AAs are commonly triggered promptly after related oracle posts (a normal, expected pattern for price-reactive AAs), this scenario is realistically reachable without any privileged or malicious-network position — it only requires an ordinary oracle-posting address and an ordinary AA trigger sender, both of which are unprivileged actors covered by the analog scope.

### Recommendation
Make the two `in_data_feed`/`data_feed` equality "interfaces" verifiably equivalent: have the unstable/in-memory fast path in `dataFeedExists()` reuse the exact same numeric normalization (`string_utils.toNumber` + type-tagged comparison) that the persisted `dataFeedByAddressExists()` path uses, instead of `.toString()` comparison, so that equality/relation results are identical regardless of whether the referenced oracle unit is stable or still unstable at evaluation time.

### Proof of Concept
1. An oracle address posts a `data_feed` message with payload `{"price": "5.0"}` in a unit `U`.
2. Before `U` stabilizes, a trigger unit `T` is sent to an AA whose formula contains `in_data_feed([oracle], 'price', '=', 5)` (numeric `5`).
3. While `U` is still unstable, `dataFeedExists()` takes the `bAA` fast path: `value.toString()` (`"5"`) is compared against `feed_value.toString()` (`"5.0"`) → **not equal** → predicate evaluates `false`, causing the AA to bounce or take the "else" branch.
4. After `U` stabilizes, the same predicate re-evaluated via `dataFeedByAddressExists()` normalizes both `5` and `"5.0"` to the same lexicographically-encoded float key → predicate evaluates `true`.
5. Because the two evaluations of the "same" oracle content give opposite results depending purely on unit-stability timing (not on the reported value), any AA logic relying on `in_data_feed` equality for state/fund decisions can be manipulated by controlling the textual representation and timing of the oracle post relative to the triggering unit. [2](#0-1) [6](#0-5)

### Citations

**File:** data_feeds.js (L13-55)
```javascript
function dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, max_mci, bAA, handleResult){
	var start_time = Date.now();
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	if (bAA) {
		var bFound = false;
		function relationSatisfied(v1, v2) {
			switch (relation) {
				case '<': return (v1 < v2);
				case '<=': return (v1 <= v2);
				case '>': return (v1 > v2);
				case '>=': return (v1 >= v2);
				default: throw Error("unknown relation: " + relation);
			}
		}
		function valueIsNumber() {
			if (typeof value === 'string') {
				const float = string_utils.toNumber(value, bLimitedPrecision);
				return float !== null;
			}
			return true;
		}
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
			storage.assocUnstableMessages[unit].forEach(function (message) {
				if (message.app !== 'data_feed')
					return;
				var payload = message.payload;
				if (!ValidationUtils.hasOwnProperty(payload, feed_name))
					return;
				var feed_value = payload[feed_name];
				if (relation === '=') {
					if (value === feed_value || value.toString() === feed_value.toString())
						bFound = true;
					return;
				}
```

**File:** data_feeds.js (L92-97)
```javascript
			if (bFound)
				break;
		}
		if (bFound)
			return handleResult(true);
	}
```

**File:** data_feeds.js (L110-137)
```javascript
function dataFeedByAddressExists(address, feed_name, relation, value, min_mci, max_mci, handleResult){
	if (relation === '!='){
		// comparison only makes sense within the same type, otherwise 'abc' != 123 but we don't want to say that they are not equal, because they are incomparable
		return dataFeedByAddressExists(address, feed_name, '>', value, min_mci, max_mci, function(bFound){
			if (bFound)
				return handleResult(true);
			dataFeedByAddressExists(address, feed_name, '<', value, min_mci, max_mci, handleResult);
		});
	}
	var prefixed_value;
	var type;
	if (typeof value === 'string'){
		var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
		var float = string_utils.toNumber(value, bLimitedPrecision);
		if (float !== null){
			prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(float);
			type = 'n';
		}
		else{
			prefixed_value = 's\n'+value;
			type = 's';
		}
	}
	else{
		prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(value);
		type= 'n';
	}
	var strMinMci = string_utils.encodeMci(min_mci);
```

**File:** main_chain.js (L1587-1616)
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
```
