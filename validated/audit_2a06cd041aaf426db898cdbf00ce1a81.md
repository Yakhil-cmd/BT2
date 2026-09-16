Found it: the `data_feed` oracles handling in `formula/evaluation.js` splits the `oracles` string on `:` without any limit on the number of resulting addresses, unlike the equivalent `readDataFeedValueByParams` path in `data_feeds.js` which explicitly caps `oracles.length > 10`.

### Title
Unbounded oracle-address list in `in_data_feed`/`data_feed` formula evaluation causes unbounded per-address data-feed lookups - (File: formula/evaluation.js)

### Summary
The `getDataFeed()` function inside the `data_feed` / `in_data_feed` oscript evaluation splits the caller-supplied `oracles` string on `:` with no cap on the resulting array size, then passes the full array to `dataFeeds.readDataFeedValue()`, which iterates it with `async.eachSeries` doing one KV-store range scan per address.

### Finding Description
In `formula/evaluation.js`, the `data_feed` case builds `arrAddresses` directly from user data: [1](#0-0) 
This differs from the sibling entry point `readDataFeedValueByParams()` in `data_feeds.js`, which validates the oracle list and explicitly rejects lists over 10 addresses: [2](#0-1) 
No such check exists on the `oracles.value.split(':')` path used by the `data_feed`/`in_data_feed` oscript operator. The formula-level structural validation in `formula/validation.js` (`validateDataFeedExists`) also only checks that the oracle string isn't empty and that each `:`-delimited segment is a valid address — it never bounds the count, and even has the complexity increment for the number of oracles explicitly commented out: [3](#0-2) 
The only outer constraint is the general oscript string-length ceiling `MAX_AA_STRING_LENGTH`, which is large enough (worth noting valid addresses are 32 chars, so even a modest string yields many addresses) to admit hundreds of `:`-separated 32-character addresses in a single `oracles` parameter, each of which triggers a full `dataFeedByAddressExists`/`readDataFeedByAddress` KV-store stream lookup in `data_feeds.js`.

### Impact Explanation
An AA whose oscript uses `in_data_feed[oracles="A1:A2:...:AN"]` or `data_feed[oracles=...]` where the `oracles` string comes from (or is influenced by) trigger data can force the evaluating node to perform hundreds of sequential key-value range scans for every trigger execution, and — because all full nodes must evaluate the AA identically to reach consensus on the response — this cost is imposed on every validating node in the network for each such trigger. This is a resource-exhaustion / node-slowdown vector reachable from an unprivileged AA trigger sender, but it manifests as increased per-unit validation latency across the network's AA execution rather than as a direct fund loss, supply inflation, or double-spend, since AA evaluation still eventually completes and the complexity/count_ops accounting caps other aspects of execution.

### Likelihood Explanation
Any address can trigger an AA that uses `in_data_feed`/`data_feed` with an oracle list influenced by trigger data or hard-coded by the AA author with an intentionally long `:`-joined list; the trigger sender does not need any special privilege, matching the reachable-actor set (AA trigger sender / AA author).

### Recommendation
Add an explicit maximum count check (mirroring the `oracles.length > 10` guard already present in `data_feeds.js`'s `readDataFeedValueByParams`) to `getDataFeed()` in `formula/evaluation.js`, and to `validateDataFeedExists()` in `formula/validation.js`, rejecting `oracles` strings whose `:`-split address count exceeds a fixed cap (e.g., 10), and reinstating/adding a complexity charge proportional to the number of oracle addresses so the AA's overall complexity budget reflects the true per-trigger execution cost.

### Proof of Concept
1. Deploy an AA whose bounce/response logic includes:
   `in_data_feed[oracles="ADDR1:ADDR2:...:ADDR200", feed_name="x"]`
   where `ADDR1..ADDR200` are 200 concatenated valid 32-character addresses (well within `MAX_AA_STRING_LENGTH`), passing `validateDataFeedExists` structural checks since each segment is a valid address and the string is non-empty.
2. Send a trigger unit to this AA from any unprivileged address.
3. During AA execution, `formula/evaluation.js`'s `data_feed` handler splits the oracle string into 200 addresses and calls `dataFeeds.readDataFeedValue(arrAddresses, ...)`, which runs `async.eachSeries` over all 200 addresses, each opening a `kvstore.createReadStream` — 200 sequential KV scans triggered by a single formula evaluation on a single AA response, imposed on every validating node processing the trigger.

### Citations

**File:** formula/evaluation.js (L602-607)
```javascript
				function getDataFeed(params, cb) {
					if (typeof params.oracles.value !== 'string')
						return cb("oracles not a string "+params.oracles.value);
					var arrAddresses = params.oracles.value.split(':');
					if (!arrAddresses.every(ValidationUtils.isValidAddress))
						return cb("bad oracles "+arrAddresses);
```

**File:** data_feeds.js (L346-351)
```javascript
	if (!ValidationUtils.isNonemptyArray(oracles))
		return cb("oracles must be non-empty array");
	if (!oracles.every(ValidationUtils.isValidAddress))
		return cb("some oracle addresses are not valid");
	if (oracles.length > 10)
		return cb("too many oracles");
```

**File:** formula/validation.js (L105-111)
```javascript
			case 'oracles':
				if (value.trim() === '') return {error: 'empty oracles', complexity};
				var addresses = value.split(':');
				if (addresses.length === 0) return {error: 'empty oracles list', complexity};
			//	complexity += addresses.length;
				if (!addresses.every(ValidationUtils.isValidAddress)) return {error: 'not valid oracle address', complexity};
				break;
```
