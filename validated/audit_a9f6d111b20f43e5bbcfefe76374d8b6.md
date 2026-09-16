## Analog Found

### Title
Unbounded key-store scan in the `in data feed` authentifier / `dataFeedByAddressExists` check enables validation-time resource exhaustion - (File: `data_feeds.js`)

### Summary
The XWiki advisory describes a REST endpoint that enumerated *all* pages of a wiki without honoring a query limit, letting an unprivileged caller exhaust server resources with one request. The same bug class — an attacker-reachable lookup that streams through an unbounded range of stored records instead of stopping at a small limit — exists in ocore's data-feed "existence" check, `dataFeedByAddressExists`, which backs the `in data feed` address-definition operator evaluated during ordinary unit validation.

### Finding Description
`dataFeedByAddressExists` in [1](#0-0)  builds a `kvstore` range-scan (`options.gte/gt/lt/lte`) keyed only by `oracle address + feed_name + value type`, with **no `options.limit`** for the `>`, `>=`, `<`, `<=` relations (only the `=` relation sets `limit: 1`). The scan is expected to stop early via `stream.destroy()` once a record satisfying both the value relation *and* the `[min_mci, max_mci]` window is found: [2](#0-1) 

If an oracle has posted many data-feed values over time (a realistic case for long-running price feeds) and the caller chooses a relation/value that is satisfied by many records but an `mci` window (`min_mci`/`max_mci`) that never matches any of them, the stream never finds a qualifying record and must traverse the **entire** key range for that oracle/feed/type before emitting `end`, with no cap on the number of records inspected (`count`/`count_before_found` in the code are diagnostic only, not enforced limits).

This function is reached from unit validation through the `in data feed` address-definition operator: [3](#0-2) 

`in data feed` is a completely ordinary, unprivileged part of the Definition Language — any user can create an address whose definition contains `['in data feed', [['ORACLE_ADDR'], 'feed_name', '<', value, min_mci]]` and then post a unit that references this address as an author/definition (e.g., as one branch of an `or`/`and` condition, or even as the sole condition, since `validateAuthentifiers` must evaluate it to determine unit validity). Every full node that receives and validates that unit will execute the same unbounded scan synchronously during unit validation.

### Impact Explanation
Because this scan happens inside `validateAuthentifiers`, which runs during unit validation on **every full node** (not just the composer), a single crafted unit can force each validating node to spend excessive time/CPU streaming a large fraction of an oracle's entire data-feed history from the KV store. For popular, long-lived oracles that post frequently (e.g., price feeds active for years), this range can contain a very large number of entries. Repeated posting of such units (there is no extra cost beyond normal unit fees) can degrade validation throughput network-wide, matching the "network unable to confirm new units" bar — an availability impact analogous to the XWiki CVE (CWE-770, uncontrolled resource consumption via unbounded query).

### Likelihood Explanation
The `in data feed` operator with relational operators (`<`, `<=`, `>`, `>=`) is a standard, documented feature of Obyte address definitions, fully reachable by any unprivileged user who can define an address and post a unit — no special privilege, hub, or peer compromise is required. The only requirement is choosing an oracle/feed with a long posting history and a value/mci combination that never satisfies the search, which is trivial to construct (e.g., set `min_mci`/`max_mci` to a narrow historical window unrelated to any actual postings, or a value threshold satisfied by most records but combined with an mci filter matching none of them).

### Recommendation
Apply a hard cap (`options.limit`) to the `dataFeedByAddressExists` range scan for the `>`, `>=`, `<`, `<=` relations, similar to how `=` already sets `limit: 1`, and treat exceeding the cap as "not found" (or fall back to an error/bounce) rather than scanning unboundedly. Alternatively, restructure the key so that `mci` is part of the primary range boundary (as already done for `=`) so out-of-window records are excluded by the range itself instead of being iterated and rejected one by one.

### Proof of Concept
1. Identify a long-lived oracle address `ORACLE` and `feed_name` with many historical postings (e.g., a price feed posted every few minutes for years).
2. Define an address `A` with definition:
   `['in data feed', [['ORACLE'], 'feed_name', '<', <value satisfied by nearly all historical postings>, <min_mci far below any real posting's mci>]]`
   combined so that this condition alone determines validity (e.g., as a single top-level condition, or as an `and` branch that is always evaluated).
   Because `max_mci` used internally is `objValidationState.last_ball_mci` (the unit's own last-ball mci) and `min_mci` is attacker-supplied, choose `min_mci` such that no historical record's mci falls in `[min_mci, last_ball_mci]` for that feed’s address, e.g. a range that is empty due to timing gaps or oracle history layout, forcing `dataFeedByAddressExists` to scan the full remaining key range without finding a qualifying mci.
3. Post a unit spending from/authored by address `A` using this definition.
4. Every full node validating the unit calls `definition.js`'s `'in data feed'` case → `dataFeeds.dataFeedExists` → `dataFeedByAddressExists`, which streams through the oracle's entire matching-value key range in the KV store before returning, consuming disproportionate CPU/I/O per validating node relative to the trivial cost of posting the unit.

### Citations

**File:** data_feeds.js (L110-164)
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
	var strMaxMci = string_utils.encodeMci(max_mci);
	var key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value;
	var bFound = false;
	var options = {};
	switch (relation){
		case '=':
			options.gte = key_prefix+'\n'+strMaxMci;
			options.lte = key_prefix+'\n'+strMinMci;
			options.limit = 1;
			break;
		case '>=':
			options.gte = key_prefix;
			options.lt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\r';  // \r is next after \n
			break;
		case '>':
			options.gt = key_prefix+'\nffffffff';
			options.lt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\r';  // \r is next after \n
			break;
		case '<=':
			options.lte = key_prefix+'\nffffffff';
			options.gt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\n';
			break;
		case '<':
			options.lt = key_prefix;
			options.gt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\n';
			break;
	}
```

**File:** data_feeds.js (L174-187)
```javascript
	else
		handleData = function(data){
			count++;
			if (bFound)
				return;
			count_before_found++;
			var mci = string_utils.getMciFromDataFeedKey(data);
			if (mci >= min_mci && mci <= max_mci){
				bFound = true;
				console.log('destroying stream prematurely');
				stream.destroy();
				onEnd();
			}
		};
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
