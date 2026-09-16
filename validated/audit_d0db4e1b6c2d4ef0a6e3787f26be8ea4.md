### Title
Unhandled exception via malformed data-feed key parsing causes node crash on `data_feed` AA reads - (File: `data_feeds.js`, `string_utils.js`)

### Summary
The Wireshark CVE crashed a dissector because it split an untrusted string without validating the number of resulting parts before indexing into it. The same anti-pattern exists in ocore's data-feed subsystem: `feed_name` values that are embedded, unescaped, into an internal `\n`-delimited key are later re-split by `\n` and the parsed segments are indexed/counted with an assumption of a fixed layout. If the delimiter character appears inside attacker/oracle-controlled data, the split produces a different number of fields than expected, and the code throws an uncaught `Error` instead of handling it gracefully.

### Finding Description
`dataFeedByAddressExists` builds a KV-store key by directly concatenating the caller-supplied `feed_name` with `\n` separators: [1](#0-0) 

That composite key is later read back and split on `\n` with a hard assumption that it always contains exactly 6 fields: [2](#0-1) 

and `getMciFromDataFeedKey` similarly assumes the last `\n`-separated token is always the reversed MCI: [3](#0-2) 

`readDataFeedByAddress` also blindly indexes into a two-part split when reconstructing the stored value/unit pair: [4](#0-3) 

Both `getValueFromDataFeedKey` and `getMciFromDataFeedKey` are invoked from inside `kvstore` stream `'data'` event handlers (`dataFeedByAddressExists`, `readDataFeedByAddress`), which have no surrounding `try/catch`: [5](#0-4) [6](#0-5) 

If a `feed_name` (or a string `value`) written into a `data_feed` message payload contains a literal `\n` (`0x0A`) byte, the constructed key `'df\n'+address+'\n'+feed_name+'\n'+prefixed_value+'\n'+strMci` will contain extra `\n` boundaries. When such a key is later parsed back by `getValueFromDataFeedKey`, `m.length !== 6` and the function throws `Error("wrong number of elements in data feed "+key)`. Because this happens inside a KV-store stream data callback with no error handling, the exception propagates as an uncaught exception, crashing the Node.js process that is evaluating the `data_feed` condition — which happens whenever any AA trigger evaluates `data_feed[...]` conditions against oracle-posted feeds. This is directly analogous to the Wireshark TSDNS dissector crash: an untrusted string is split assuming a fixed field count without bounds/format validation, and the mismatch is not handled defensively.

Whether `feed_name`/string feed `value` are restricted from containing `\n` at the message-validation layer (`validation.js`) could not be confirmed with full certainty in this pass — the `data_feed` app payload validation was located but not fully read before the session ended, so the exact character-set/length checks applied to `feed_name` and string data-feed values remain unverified. This should be checked before treating the finding as confirmed exploitable.

### Impact Explanation
If the delimiter injection is reachable (i.e., `validation.js` does not strip/reject `\n` in `feed_name` or string data-feed values), any oracle-authored `data_feed` unit could cause deterministic crashes in every full node/AA-evaluating node that later reads that feed via `data_feed[...]` conditions in an AA, or via `dataFeedExists`/`readDataFeedValue`. Because the crash is deterministic and reproducible from data already committed to the DAG, it can be used to repeatedly halt nodes trying to process AAs referencing the poisoned feed, disrupting confirmation of new units that depend on that AA and creating potential node-to-node behavioral divergence (nodes that crash vs. restart at different points may reprocess differently). This falls under "node disagreement on validity or stability" / "network unable to confirm new units" if reachable.

### Likelihood Explanation
Likelihood depends entirely on whether `\n` is permitted in `feed_name` or string feed values by unit/message validation, which was not fully confirmed. If unrestricted, the trigger is trivial (any address, including any AA trigger sender who can also post `data_feed` messages, or any oracle) and requires no special privileges.

### Recommendation
1. In `validation.js`, explicitly reject `\n` (and any other characters used as key-delimiters, e.g. `\0`) in `data_feed` payload keys (`feed_name`) and in string values, in addition to existing length checks.
2. In `string_utils.js`, make `getValueFromDataFeedKey` and `getMciFromDataFeedKey` defensive: use a fixed-width/escaped encoding for the address/feed_name/value fields (e.g., length-prefixing) instead of naive `\n` splitting, or wrap the parsing in error handling that logs and skips the malformed record rather than throwing.
3. Add `try/catch` around the KV-store stream `'data'` handlers in `data_feeds.js` so a single malformed record cannot crash the whole read/validation flow.

### Proof of Concept
1. Craft (or, if validation does not block it, post) a `data_feed` message whose payload contains a key such as `"foo\nbar": 123` — i.e., a `feed_name` embedding a literal newline byte.
2. Once this unit is processed and the data feed key `'df\n'+address+'\n'+"foo\nbar"+'\n'+prefixed_value+'\n'+mci` is stored, trigger any AA (or call) that evaluates `data_feed[[oracles=address, feed_name='foo\nbar']]` so that `dataFeedByAddressExists`/`readDataFeedByAddress` is invoked.
3. When the stored key is streamed back and parsed by `getValueFromDataFeedKey`/`getMciFromDataFeedKey`, `key.split('\n')` yields more than the expected number of segments, `m.length !== 6` triggers `throw Error("wrong number of elements in data feed "+key)` inside the uncaught stream `'data'` callback, crashing the node process.

Note: this PoC assumes the message-validation layer does not already reject `\n` inside `feed_name`/string values — that specific check in `validation.js` was not fully verified in this analysis and should be confirmed before treating this as a live, exploitable issue.

### Citations

**File:** data_feeds.js (L137-139)
```javascript
	var strMinMci = string_utils.encodeMci(min_mci);
	var strMaxMci = string_utils.encodeMci(max_mci);
	var key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value;
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

**File:** data_feeds.js (L312-330)
```javascript
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

**File:** string_utils.js (L67-73)
```javascript
function getMciFromDataFeedKey(key){
	var arrParts = key.split('\n');
	var strReversedMci = arrParts[arrParts.length-1];
	var reversed_mci = parseInt(strReversedMci, 16);
	var mci = 0xFFFFFFFF - reversed_mci;
	return mci;
}
```

**File:** string_utils.js (L76-83)
```javascript
function getValueFromDataFeedKey(key){
	var m = key.split('\n');
	if (m.length !== 6)
		throw Error("wrong number of elements in data feed "+key);
	var type = m[3];
	var value = m[4];
	return (type === 's') ? value : decodeLexicographicToDouble(value);
}
```
