### Title
AA data-feed formula results bypass length/`\n` validation, corrupting data-feed keyspace - (File: aa_validation.js)

### Summary
`AA` definition validation in `aa_validation.js` only enforces `MAX_DATA_FEED_NAME_LENGTH` / `MAX_DATA_FEED_VALUE_LENGTH` and the "no `\n`" rule when a `data_feed` message's `feed_name`/`value` is a **literal** string. When the field is a formula (`getFormula(...) !== null`), all of these checks are skipped entirely, because the actual value is only known at trigger-evaluation time and is never re-validated against the same bounds before being written into the leveldb data-feed keyspace.

### Finding Description
In `validatePayload`'s `data_feed` case: [1](#0-0) 
the length/`\n` checks are guarded by `if (feed_name_formula === null)` and `if (value_formula === null)` — i.e. they run only for the non-formula branch. When a formula is used, no bound is ever verified. This mirrors the CVE-2023-38545 bug class exactly: a state check ("is this data trusted/bounded, or does it need special handling") that correctly limits the size/content of one code path (the literal path) is silently skipped on a sibling path (the formula path) that ultimately writes into a fixed-format buffer.

That fixed-format "buffer" here is the leveldb key/value structure built once the AA fires and the formula is evaluated, in `main_chain.js`'s `addDataFeeds`: [2](#0-1) 
Keys are built by naive string concatenation using `\n` as the field delimiter: `'df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci` and `'dfv\n'+address+'\n'+feed_name+'\n'+strMci`. Nothing here re-checks length or the presence of `\n` in `feed_name`/`value` — that check exists only for the literal path in `aa_validation.js` (and its non-AA counterpart in `validation.js`): [3](#0-2) 

Because AA `data_feed` payloads allow `feed_name` and values to be arbitrary formulas (e.g. built from `trigger.data.*`, string concatenation, etc.), an attacker who triggers the AA can make the *evaluated* `feed_name` or `value` string contain embedded `\n` characters and/or be far longer than `MAX_DATA_FEED_NAME_LENGTH`/`MAX_DATA_FEED_VALUE_LENGTH`. Since the delimiter-based key format assumes `feed_name` cannot itself contain `\n`, an injected newline effectively adds extra "segments" to the `df\n`/`dfv\n` key, changing how `readDataFeedByAddress`'s prefix-range queries interpret the key structure: [4](#0-3) 

### Impact Explanation
`in data feed` oracle conditions in address/AA definitions, and the `data_feed()`/`in_data_feed` formula operators, rely on the assumption that `feed_name` is an opaque token bounded to at most `MAX_DATA_FEED_NAME_LENGTH` bytes with no `\n`, so that prefix-based leveldb range scans (`df\n<address>\n<feed_name>\n...`) unambiguously resolve to the intended feed. If an AA can be induced (via attacker-supplied trigger data flowing into a formula-based `feed_name`/value) to write a data feed entry whose name contains a `\n`, the entry's key now straddles what a consumer's range query treats as separate fields. This can let an attacker forge or shadow a data-feed entry that a *different* consuming address definition/AA logic reads as if it came from a legitimate oracle for a different `feed_name`/value combination — a form of oracle/data-feed spoofing that can flip conditional spending logic (`in data feed` conditions) or AA formula branches that gate fund transfers, i.e., a path to unauthorized AA fund release.

Because this evaluation happens deterministically inside `handleTrigger`/`markMcIndexStable`, every full node computes the same (corrupted) key on the same trigger, so it does not by itself cause node disagreement — but it can corrupt oracle/data-feed lookups used by *other* independent addresses/AAs that trust the feed, enabling fund loss/release conditions to be satisfied illegitimately.

### Likelihood Explanation
Any account able to post a trigger unit to an `AA` whose `messages` include a `data_feed` app with a formula-based `feed_name` or value is sufficient to reach this code path — no privileged network position, hub trust, or protocol-level access is required, matching the "unprivileged unit poster / AA trigger sender" threat model.

### Recommendation
Re-validate the evaluated `feed_name` and value against `constants.MAX_DATA_FEED_NAME_LENGTH` / `MAX_DATA_FEED_VALUE_LENGTH` and reject/strip embedded `\n` characters in `main_chain.js`'s `addDataFeeds` (and in the `data_feed` evaluation branch of `formula/evaluation.js`) immediately before the `batch.put` calls, mirroring the checks already applied to the literal path in `validation.js:1925-1951`, so formula-derived data-feed identifiers can never violate the length/format invariants the storage layer's delimiter-based keys depend on.

### Proof of Concept
1. Deploy an AA whose `messages` contains:
```json
{
  "app": "data_feed",
  "payload": { "{trigger.data.name}": "{trigger.data.val}" }
}
```
2. Trigger the AA with `data.name` containing an embedded newline followed by attacker-chosen bytes designed to mimic a legitimate `address`/`feed_name` segment of the `df\n...` key format, and/or with `data.val` longer than `MAX_DATA_FEED_VALUE_LENGTH`.
3. Because both `feed_name` and `value` are formulas, `aa_validation.js` (lines 92-121) never rejects the AA definition or the trigger for exceeding length or containing `\n`.
4. On stabilization, `addDataFeeds` in `main_chain.js` (lines 1587-1617) writes the resulting `df\n`/`dfv\n` keys verbatim, with the injected `\n` now splitting the key into unintended segments.
5. A separate address/AA definition relying on `in data feed` for a specific `(address, feed_name)` pair can then match against the attacker-crafted entry due to the ambiguous key structure, satisfying a spending/oracle condition it should not — enabling unauthorized fund release from that address/AA.

*Note: Full confirmation that `readDataFeedByAddress`'s range-scan semantics can actually be tricked into matching a spoofed `(address, feed_name)` combination via an injected `\n` requires deeper tracing of `kvstore.createKeyStream` range boundary behavior than could be completed here; this should be verified with a live Devin session before treating this as fully proven.*

### Citations

**File:** aa_validation.js (L92-121)
```javascript
				case 'data_feed':
					if (!isNonemptyObject(payload))
						return cb2("data feed payload must be non-empty object or formula");
					for (var feed_name in payload) {
						var feed_name_formula = getFormula(feed_name);
						if (feed_name_formula === null) {
							if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
								return cb2("feed name " + feed_name + " too long");
							if (feed_name.indexOf('\n') >= 0)
								return cb2("feed name " + feed_name + " contains \\n");
						}
						var value = payload[feed_name];
						if (typeof value === 'string') {
							var value_formula = getFormula(value);
							if (value_formula === null) {
								if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
									return cb2("value " + value + " too long");
								if (value.indexOf('\n') >= 0)
									return cb2("value " + value + " of feed name " + feed_name + " contains \\n");
							}
						}
						else if (typeof value === 'number') {
							if (!isInteger(value))
								return cb2("fractional numbers not allowed in data feeds");
						}
						else
							return cb2("data feed " + feed_name + " must be string or number");
					}
					cb2();
					break;
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

**File:** data_feeds.js (L119-164)
```javascript
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
