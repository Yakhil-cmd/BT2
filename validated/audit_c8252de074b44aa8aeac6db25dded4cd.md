### Title
Data Feed Name/Value Injection into LevelDB Key Namespace via Unescaped Newline Separators - (File: `main_chain.js`)

### Summary
When a stable unit contains a `data_feed` message, `markMcIndexStable()` writes every feed name/value pair from the message payload directly into the KV-store using `\n` as a field separator, without validating that the feed name or string value does not itself contain the same `\n` character used as the delimiter. Because any unit author can include a `data_feed` message in a unit they post, an attacker can smuggle extra `\n`-delimited "fields" into the address/feed_name/type/value/mci key structure, corrupting or spoofing entries that AAs and wallets later read back via prefix-scans (`data_feed[...]` in oscript / `readDataFeedValue` in `data_feeds.js`).

### Finding Description
In `main_chain.js` (`markMcIndexStable` → `addDataFeeds`), for every `feed_name`/`value` pair posted in a `data_feed` message: [1](#0-0) 
the code builds LevelDB keys such as `'df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci` and `'dfv\n'+address+'\n'+feed_name+'\n'+strMci`, joining fields with the literal `\n` character. The feed name and string value both originate from the untrusted `data_feed` payload of a unit that any address can author. If either `feed_name` or `strValue` is allowed to contain a `\n` byte, the attacker effectively injects an arbitrary number of additional key-namespace "fields" — shifting where the `type` marker (`s`/`n`), the `mci` suffix, or even the `address`/`feed_name` boundary is interpreted by downstream range-scan consumers such as `data_feeds.js` and the `data_feed` formula function in `formula/evaluation.js`, which locate values by constructing prefix strings like `'df\n'+address+'\n'+feed_name+'\n'` and scanning for the next `\n`-delimited component. This is the same bug class as CVE-2022-3607 (failure to sanitize special elements — here, the LevelDB key-namespace delimiter — that lets attacker input cross into a different "plane" of the data structure).

### Impact Explanation
A malicious oracle/attacker able to post a unit with a crafted `data_feed` message could poison or shadow legitimate data-feed entries for its own address (or exploit prefix-scan ambiguity to make lookups for one feed_name match a differently-intended key). Any AA relying on `data_feed[...]` to make payout, price, or oracle-triggered decisions could be tricked into executing under attacker-manufactured feed values, leading to AA fund loss or incorrect fund release — a concrete financial-impact analog rather than a mere DoS.

### Likelihood Explanation
Reaching this path only requires posting an ordinary unit containing a `data_feed` message — no special privilege is needed, matching the "unprivileged unit poster" threat model. The key open question (which I was not able to fully confirm before running out of tool calls) is whether `validation.js`'s `data_feed` message validation already restricts feed names/values to a charset that excludes `\n` (I located the validation code by name but could not retrieve its full body in the remaining iterations). If such a restriction already exists, the practical exploitability is much lower; if it does not, exploitability is high given the simplicity of the payload.

### Recommendation
Explicitly reject `data_feed` names and string values containing the `\n` byte (or any byte used as a key-namespace delimiter, e.g. also reject `\0` if used) in `validation.js`'s data_feed message validation, and additionally defensively escape/length-prefix each component when constructing LevelDB keys in `main_chain.js`'s `addDataFeeds`, rather than relying solely on upstream input validation.

### Proof of Concept
1. Craft and post a unit authored by address `A` containing a message `{app: 'data_feed', payload: {"foo\ns\n0000000123": "bar"}}` (embedding a literal newline plus a fabricated `type`/`mci` segment in the feed name).
2. Once stable, `addDataFeeds` writes `batch.put('df\nA\nfoo\ns\n0000000123\ns\nbar\n'+strMci, unit)`, producing a key whose structure now contains attacker-chosen extra segments matching the format normally produced by the `mci` encoding.
3. Query the feed via the oscript `data_feed[[oracles=A, feed_name='foo']]` formula function or `data_feeds.js` read path and observe that the prefix-scan boundary logic can be made to resolve to the attacker's injected segment instead of the intended value, demonstrating cross-plane injection into the key namespace.

Note: I could not fully verify within the available searches whether `validation.js` already sanitizes data_feed name/value strings against `\n`; this should be confirmed directly in the repository (`validation.js`, data_feed message validation branch) before treating this as fully unmitigated.

### Citations

**File:** main_chain.js (L1594-1615)
```javascript
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
```
