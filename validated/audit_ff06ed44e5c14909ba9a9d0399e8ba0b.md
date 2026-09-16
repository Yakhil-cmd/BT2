### Title
Data Feed Name Delimiter Injection Forges Data-Feed Key Boundaries in `data_feeds.js` - (File: data_feeds.js)

### Summary
The ZITADEL advisory describes LDAP filter injection where user-supplied usernames are concatenated into an LDAP search filter without escaping the LDAP metacharacters (`*`, `(`, `)`), letting an attacker manipulate query semantics to enumerate directory data. The structural analog in ocore is the data-feed key-value store lookup layer, where the `feed_name` string supplied inside a `data_feed` message payload is concatenated directly into LevelDB range-query keys using `\n` as the field delimiter, without any check that `feed_name` itself does not contain the `\n` delimiter character.

### Finding Description
Data feed values are stored and queried as delimited LevelDB keys of the form `df\n<address>\n<feed_name>\n<type>\n<value>\n<mci>` and `dfv\n<address>\n<feed_name>\n<mci>`, built in `main_chain.js` (`batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit)`) [1](#0-0) , and later read back by concatenating the same `feed_name` into `gte`/`lte`/`gt`/`lt` range boundaries in `dataFeedByAddressExists` and `readDataFeedByAddress`: [2](#0-1) [3](#0-2) 

`feed_name` is fully attacker/oracle-controlled — it is simply a JS object key of the `data_feed` message payload that any unit author can post. Unlike the LDAP case where `*`, `(`, `)` are the filter metacharacters, here `\n` is the field-boundary metacharacter of the key scheme. If `feed_name` (or an oracle's chosen feed name in general) is not restricted from containing `\n`, an attacker can craft a feed name that itself embeds `\n`-separated fragments resembling a `type\nvalue\nmci` suffix or an `address\nfeed_name` prefix. Because LevelDB key comparisons are purely lexicographic byte-range comparisons, such an embedded delimiter can shift the computed `gte/lte` (or `gt/lt`) boundaries so that a range query for one address/feed_name/value combination incidentally matches, or fails to match, keys that belong to a logically different feed name, type, or mci window — the same "boundary confusion" root cause that makes LDAP filter injection possible when parentheses are not escaped.

The oscript surface `data_feed[[oracles=..., feed_name=..., feed_value=...]]` (evaluated in `formula/evaluation.js`, case `'data_feed'`) and the definition-level `['in data feed', ...]` authentifier condition (`definition.js`, case `'in data feed'`) both funnel an oscript-supplied `feed_name` string straight into `dataFeeds.readDataFeedValue` / `dataFeeds.dataFeedExists`, which in turn call the vulnerable key-building functions: [4](#0-3) [5](#0-4) 

This means both an AA author writing `data_feed[[...]]` in a template, and a wallet author using `in data feed` in an address definition, can be affected by whatever malicious `feed_name` an oracle chooses to post, and the AA/definition evaluation trusts the KV-store range lookup to correctly scope by feed name.

### Impact Explanation
If a malicious oracle (an ordinary unit poster of a `data_feed` message — no special privilege required) chooses a `feed_name` containing embedded `\n` sequences designed to mimic type/value/mci separators, it could cause `dataFeedByAddressExists`/`readDataFeedByAddress` range scans to return matches for a *different* feed name, type, or mci window than the one an AA or address definition actually queried. Since AAs commonly gate fund transfers or price computations on data-feed results (`data_feed[[...]]`) and address definitions can gate spending authorization on `in data feed`, a forged/cross-boundary match can cause an AA to act on an unintended value (fund loss/misdirection) or cause a definition-based authorization check to unexpectedly pass/fail, leading to disagreement between nodes on validity if evaluation depends on interpretation of the scan results. This lands squarely in the "AA fund loss or freezing" / "node disagreement on validity" impact categories allowed by the rules.

### Likelihood Explanation
`feed_name` is an attacker-controlled JS object key with no evidence found (within the scope of what could be inspected) that the `data_feed` message validation path in `validation.js` rejects control characters such as `\n` inside a feed-name field — length limits (`MAX_DATA_FEED_NAME_LENGTH`) and "well-formedness" (UTF-16 validity) checks referenced in `constants.js`/`string_utils.js`/`aa_validation.js` do not by themselves exclude the `\n` character. Any unit author can post such a message, and any AA or address definition that consumes matching data feeds is automatically exposed, making this reachable from a single posted unit with no special role, consistent with the required "unprivileged unit poster" reachability. I was not able to fully re-verify, within the remaining tool budget, whether a `\n`-specific character check exists deeper in the validation path for the `data_feed` app payload field names; this residual uncertainty should be resolved by direct code review of the `data_feed` case in `validation.js`.

### Recommendation
Reject (or normalize) `feed_name`/data-feed field names that contain the `\n` (and ideally any control) character at message-validation time in `validation.js`'s `data_feed` case, and additionally add a defensive check in `dataFeedByAddressExists`/`readDataFeedByAddress`/`main_chain.js`'s data-feed key writer to refuse building keys from any component (`address`, `feed_name`) containing the `\n` delimiter, so that key-range boundaries can never be manipulated by payload content.

### Proof of Concept
1. Attacker posts a unit with a `data_feed` message whose payload contains a crafted key, e.g. `{"real_feed\nn\n<lexicographically-encoded-value>\n<crafted_mci>": "irrelevant"}` where the embedded fragment is designed to overlap with the byte-range boundaries computed in `dataFeedByAddressExists`/`readDataFeedByAddress` for a different, legitimate `feed_name`/`value`/`mci` combination that an AA or address definition subsequently queries.
2. An AA (or address definition using `in data feed`) executes `data_feed[[oracles=<attacker_address>, feed_name='real_feed', ...]]` (or the corresponding `['in data feed', ...]` authentifier).
3. Because the LevelDB range scan in `dataFeedByAddressExists`/`readDataFeedByAddress` relies purely on lexicographic ordering of the `\n`-joined key components, the crafted `feed_name` value can cause the scan's `gte/lte` bounds to include or exclude keys unintended by the querying AA/definition author, yielding a data-feed match/no-match result that differs from what a correctly delimited feed name would produce — analogous to how unescaped LDAP metacharacters let an attacker widen or narrow a directory filter's matching scope.

*(This proof of concept describes the exploitation mechanism based on the key-construction code reviewed; a concrete byte-for-byte crafted `feed_name` was not empirically executed against a running node within this investigation and should be validated experimentally.)*

### Citations

**File:** main_chain.js (L1607-1615)
```javascript
										arrAuthorAddresses.forEach(function(address){
											// duplicates will be overwritten, that's ok for data feed search
											if (strValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit);
											if (numValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\nn\n'+numValue+'\n'+strMci, unit);
											// if several values posted on the same mci, the latest one wins
											batch.put('dfv\n'+address+'\n'+feed_name+'\n'+strMci, value+'\n'+unit);
										});
```

**File:** data_feeds.js (L139-164)
```javascript
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

**File:** data_feeds.js (L287-311)
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
```

**File:** formula/evaluation.js (L602-646)
```javascript
				function getDataFeed(params, cb) {
					if (typeof params.oracles.value !== 'string')
						return cb("oracles not a string "+params.oracles.value);
					var arrAddresses = params.oracles.value.split(':');
					if (!arrAddresses.every(ValidationUtils.isValidAddress))
						return cb("bad oracles "+arrAddresses);
					var feed_name = params.feed_name.value;
					if (!feed_name || typeof feed_name !== 'string')
						return cb("empty feed_name or not a string");
					var value = null;
					var relation = '';
					var min_mci = 0;
					if (params.feed_value) {
						value = params.feed_value.value;
						relation = params.feed_value.operator;
						if (!isValidValue(value))
							return cb("bad feed_value: "+value);
					}
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
					var what = 'value';
					if (params.what){
						what = params.what.value;
						if (what !== 'unit' && what !== 'value')
							return cb("bad what: "+what);
					}
					var type = 'auto';
					if (params.type){
						type = params.type.value;
						if (type !== 'string' && type !== 'auto')
							return cb("bad df type: "+type);
					}
					if (params.ifnone && !isValidValue(params.ifnone.value))
						return cb("bad ifnone: "+params.ifnone.value);
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
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
