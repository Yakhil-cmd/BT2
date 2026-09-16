### Title
Data-feed key injection via unsanitized `feed_name`/value strings containing `\n` delimiters - (File: `main_chain.js`, `data_feeds.js`)

### Summary
`ocore` builds all data-feed storage keys and range-query boundaries by naively concatenating `address`, `feed_name`, `type` and `value` with a literal `"\n"` delimiter, exactly the same bug class as the reported `getBaseEntropy`/`getSignIdentity` issue: user-controlled strings are spliced into a delimiter-separated context without checking for the delimiter character itself. Because `feed_name` and string data-feed values are fully attacker-controlled (any address can post a `data_feed` message), an attacker can embed `\n` characters to break the intended field boundaries of the stored key and of the range-scan prefixes used to answer `data_feed[]` conditions inside AA formulas.

### Finding Description
Data-feed values are written with `\n` as the field separator, with `feed_name` and `value` taken directly from the posted unit's message payload: [1](#0-0) 

The identical pattern is used when reading/searching feeds, where a `key_prefix` and its adjacent upper/lower bounds are built the same way and compared lexicographically against stored keys: [2](#0-1) 

and: [3](#0-2) 

`getMciFromDataFeedKey`/`getValueFromDataFeedKey` also blindly `split('\n')` the stored key and index into fixed positions, assuming `feed_name`/`value` never contain `\n`: [4](#0-3) 

Unlike `getSourceString` in the same file, which explicitly rejects the `STRING_JOIN_CHAR` (`\x00`) inside string values/keys to prevent exactly this class of ambiguity, no equivalent check exists for the `\n`-delimited data-feed key format: [5](#0-4) 

If `feed_name` (or a string `value`) contains an embedded `\n`, the stored key `df\n<address>\n<feed_name-with-\n>\n<type>\n<value>\n<mci>` no longer has a stable field layout: an attacker-chosen `feed_name` can be crafted so that, after the injected `\n`, the remaining bytes are attacker-chosen "type"/"value"/mci-like content. Any consumer that parses the key positionally (`getValueFromDataFeedKey`, `getMciFromDataFeedKey`) or that computes range boundaries by re-concatenating a *different* (query-side) `feed_name` can be tricked into matching, splitting, or bounding on the wrong logical field, because the writer-side and reader-side assumptions about "where `feed_name` ends" diverge.

### Impact Explanation
`data_feed[]`/`in_data_feed[]` conditions are used pervasively by autonomous agents (oracles, prediction markets, price feeds) to decide fund flows. If key parsing/range comparison can be desynchronized by an attacker who fully controls the string content of a `data_feed` message they post from their own address, an AA that queries a *specific* `feed_name`/relation could be made to read a manipulated value/mci pairing that does not correspond to what the honest oracle intended for that literal feed name, leading to AA fund-flow decisions (payouts, unlocks) based on forged/ambiguous data-feed matches. This falls into the "AA fund loss" / "node disagreement on validity" impact class since two nodes could theoretically disagree on `getValueFromDataFeedKey`/mci extraction results if the number of `\n`-split segments diverges from the expected 6, causing a thrown "wrong number of elements" error on one path but not another, or different value extraction depending on internal state (e.g., cache) — a stability/consensus-relevant computation performed identically by all full nodes but based on unsanitized attacker input.

### Likelihood Explanation
Any address (a regular wallet, not a privileged operator) can post a `data_feed` message with an arbitrary `feed_name` string and arbitrary string values, requiring no special privilege — matching the "unprivileged unit poster" reachability bar. The only gate is whatever `validation.js`/`aa_validation.js` enforce on the `data_feed` message payload; I was not able to fully confirm during this scan whether those validators already reject `\n` (or other control characters) inside `feed_name`/string values, so it is uncertain whether this is currently exploitable end-to-end or already blocked upstream of `addDataFeeds`.

### Recommendation
Explicitly reject `feed_name` and string data-feed values containing the delimiter character `\n` (and ideally all control characters) at unit-validation time, in the same spirit as `getSourceString`'s existing `STRING_JOIN_CHAR` check, before the value ever reaches `addDataFeeds` in `main_chain.js` or the key-construction/range logic in `data_feeds.js`. Alternatively, switch to a length-prefixed or otherwise unambiguous encoding for data-feed keys so no character choice by the poster can shift field boundaries.

### Proof of Concept
Not independently verified end-to-end (would require confirming whether `validation.js`'s `data_feed` payload checks already strip/reject `\n`); the concrete reachable primitive is: post a unit with message `{"app":"data_feed","payload":{"legit_feed\nn\n<attacker_encoded_value>\n<attacker_mci>":"whatever"}}` from an ordinary address, causing `addDataFeeds` (`main_chain.js:1607-1615`) to persist a kvstore key whose byte layout diverges from the 6-field format assumed by `getValueFromDataFeedKey`/`getMciFromDataFeedKey` (`string_utils.js:67-83`) and by the range-boundary construction in `dataFeedByAddressExists`/`readDataFeedByAddress` (`data_feeds.js:137-163`, `291-311`).

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

**File:** data_feeds.js (L137-163)
```javascript
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
```

**File:** data_feeds.js (L291-311)
```javascript
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

**File:** string_utils.js (L11-22)
```javascript
function getSourceString(obj) {
	var arrComponents = [];
	function extractComponents(variable){
		if (variable === null)
			throw Error("null value in "+JSON.stringify(obj));
		switch (typeof variable){
			case "string":
				if (variable.includes(STRING_JOIN_CHAR))
					throw Error("00 byte in string value in " + JSON.stringify(obj));
				arrComponents.push("s", variable);
				break;
			case "number":
```

**File:** string_utils.js (L63-83)
```javascript
function encodeMci(mci){
	return (0xFFFFFFFF - mci).toString(16).padStart(8, '0'); // reverse order for more efficient sorting as we always need the latest
}

function getMciFromDataFeedKey(key){
	var arrParts = key.split('\n');
	var strReversedMci = arrParts[arrParts.length-1];
	var reversed_mci = parseInt(strReversedMci, 16);
	var mci = 0xFFFFFFFF - reversed_mci;
	return mci;
}

// df:address:feed_name:type:value:strReversedMci
function getValueFromDataFeedKey(key){
	var m = key.split('\n');
	if (m.length !== 6)
		throw Error("wrong number of elements in data feed "+key);
	var type = m[3];
	var value = m[4];
	return (type === 's') ? value : decodeLexicographicToDouble(value);
}
```
