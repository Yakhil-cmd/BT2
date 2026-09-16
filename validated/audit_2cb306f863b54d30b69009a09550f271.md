### Title
Unescaped `feed_name`/value fields let a unit poster inject `\n` delimiters into data-feed KV-store keys, corrupting lookups by `data_feed()`/`in_data_feed()` - ([File: data_feeds.js])

### Summary
`data_feeds.js` and the stabilization code in `main_chain.js` build RocksDB keys for data feeds by directly concatenating attacker-controlled `feed_name` and value strings with `\n` as a field separator, without escaping or rejecting `\n` inside those fields. This mirrors the reported bug class: untrusted data is spliced unencoded into a structured, delimiter-based identifier (there a URL path, here a KV-store key), letting the attacker's payload escape its intended field and corrupt the structure that downstream code parses positionally.

### Finding Description
When a unit becomes stable, `addDataFeeds()` in `main_chain.js` writes each `data_feed` message's fields into the key-value store using `\n`-joined keys: [1](#0-0) 

The same unescaped concatenation is used when querying, in `dataFeedByAddressExists()` and `readDataFeedByAddress()`: [2](#0-1) [3](#0-2) 

Downstream parsers assume a fixed, positional `\n`-delimited layout and blindly split by `\n`: [4](#0-3) 

`getValueFromDataFeedKey()` even hard-asserts `m.length !== 6` and throws if the split produces an unexpected number of parts — proof that the code assumes `feed_name` (and the string value) never contain the `\n` separator it uses to build/parse the key. Nothing in the reachable code paths shown (message construction in `data_feeds.js`/`main_chain.js`) escapes or rejects `\n` (or other structural bytes) in `feed_name` before it is spliced into the key. `feed_name` and string data-feed values originate directly from an untrusted `data_feed` message payload posted by any unit author (or from an AA trigger's own data-feed message), i.e. from a single unprivileged unit poster — the same trust boundary as the "path variable" in the original advisory.

If `feed_name` (or a string value) is crafted to contain `\n`, it can inject extra pseudo-fields into the key, shifting what a subsequent `split('\n')` treats as `address`, `type`, `value`, or `mci`. This is directly analogous to the advisory's core defect: an untrusted string spliced unencoded into a delimiter-structured identifier, changing which "resource" (there, an API endpoint; here, a KV range/record) ends up being addressed.

### Impact Explanation
`data_feed()` and `in_data_feed()` oscript functions (used pervasively by AAs) rely on these keys to look up oracle-posted values that drive AA logic (e.g., price feeds, oracle attestations used for conditional payouts). If key construction/parsing can be desynchronized by attacker-chosen `feed_name`/value content containing `\n`, an oracle-adjacent poster (or any unit author acting as their own "oracle" feed for an AA that reads its own data feeds) could cause:
- range-scan queries (`gte`/`lte`/`gt`/`lt` prefix bounds built the same way) to match unintended keys, returning a wrong value/unit to the AA,
- or corrupt records that make `getValueFromDataFeedKey` throw (Error thrown mid-stream on real data), destabilizing the node's ability to process stabilization for units referencing that feed, since `addDataFeeds` runs unconditionally during `markMcIndexStable`.

Either outcome can cause an AA to compute wrong balances or misapplied payout logic (fund loss/freezing), or cause divergent behavior between full nodes if key injection is exploited in ways sensitive to on-disk key ordering (potential node disagreement on the effective feed value used at a given MCI).

### Likelihood Explanation
Any unit author can post a `data_feed` message with an arbitrary payload; the JSON payload object key (`feed_name`) is not shown to be restricted against embedding `\n`, nor is a string data-feed value. This makes the primitive trivially reachable by an unprivileged unit poster with no special privileges — matching the CVE's "unprivileged caller controlling a supposedly-safe identifier" pattern. Exploiting it into concrete fund-impacting behavior requires an AA that both consumes attacker-influenced feed names/values via `data_feed`/`in_data_feed` and trusts the returned "match" without additional sanity checks — a plausible but not universal AA design pattern.

### Recommendation
Reject or escape `\n` (and any other bytes used as the KV key field separator) in `feed_name` and in string `data_feed` values at validation time (the message/payload validator that accepts `data_feed` messages), before they ever reach `main_chain.js`'s `addDataFeeds()` or `data_feeds.js`'s key builders. Alternatively, switch to a length-prefixed or otherwise unambiguous encoding for each field instead of raw `\n`-joining, so no value of `feed_name`/value can alter the number or boundaries of parsed fields.

### Proof of Concept
1. Attacker authors and posts a valid unit containing a `data_feed` message whose payload is `{"evil\nfeedX\nn\n<forged-double>\n": "1"}` (i.e., a `feed_name` string embedding literal `\n` characters that mimic the `type`/`value` structure of the key).
2. Once the unit stabilizes, `addDataFeeds()` in `main_chain.js` writes this into the KV store verbatim: `'df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci`, producing a key with extra, attacker-chosen `\n`-delimited segments.
3. A subsequent `data_feed('feed_name'='feedX', ...)` lookup (or a range scan by another feed name/prefix) performed by `dataFeedByAddressExists`/`readDataFeedByAddress`, whose prefix bounds are built the same unescaped way, can match this forged key due to the injected separators aligning with the expected prefix/`type` boundary, returning the attacker's value/unit for a feed name the attacker does not actually own the semantics of — or triggering the `Error("wrong number of elements in data feed ...")` in `getValueFromDataFeedKey` when a legitimate lookup's stream encounters the malformed record.

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

**File:** data_feeds.js (L137-139)
```javascript
	var strMinMci = string_utils.encodeMci(min_mci);
	var strMaxMci = string_utils.encodeMci(max_mci);
	var key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value;
```

**File:** data_feeds.js (L290-305)
```javascript
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
```

**File:** string_utils.js (L67-83)
```javascript
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
