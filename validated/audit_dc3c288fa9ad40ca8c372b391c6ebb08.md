## Title
Missing tie-break validation in `readDataFeedValue()` allows an unprivileged data-feed poster to crash a full node during AA execution — (File: `data_feeds.js`)

### Summary
The CVE describes FRR's `rfapiRibBi2Ri()` crashing the process because it fails to validate/handle certain fields of an attacker-supplied BGP UPDATE before converting it into an internal route structure — an uncaught fault triggered by untrusted network input causes a Denial of Service. The equivalent weakness in ocore is in `readDataFeedValue()` in `data_feeds.js`, which builds a candidate list of *unstable* data-feed messages and then **assumes** the candidates can always be strictly ordered. When two candidate data-feed posts tie on both `latest_included_mc_index` and `level` (a condition that a normal, unprivileged unit poster can trivially engineer), the sort comparator falls through to an unconditional `throw Error(...)`, which is never caught by the caller chain and crashes the node process.

### Finding Description
`readDataFeedValue()` scans `storage.assocUnstableMessages` for `data_feed` messages from the oracle address(es), builds `arrCandidates`, and — when there is more than one candidate and the caller did not request `'abort'` and is not `bIncludeAllUnstable` — sorts them: [1](#0-0) 

```js
arrCandidates.sort(function (a, b) {
    if (a.latest_included_mc_index < b.latest_included_mc_index) return -1;
    if (a.latest_included_mc_index > b.latest_included_mc_index) return 1;
    if (a.level < b.level) return -1;
    if (a.level > b.level) return 1;
    if (bIncludeAllUnstable) // still ambiguous, sort randomly (it's OK outside AAs)
        return 1;
    throw Error("can't sort candidates "+a+" and "+b);
});
``` [2](#0-1) 

This function is invoked directly from AA (autonomous agent) formula evaluation for the `data_feed` operator, passing `bAA` (a boolean, not the string `'all_unstable'`) as `unstable_opts`: [3](#0-2) 

Because `unstable_opts` is `true` (not the literal string `'all_unstable'`), `bIncludeAllUnstable` evaluates to `false` inside `readDataFeedValue`, so the `throw` branch is fully reachable for ordinary AA trigger processing whenever two unstable candidate messages tie in `latest_included_mc_index` and `level`.

An unprivileged user (the address used as the AA's declared "oracle") can trivially create this tie: post two sibling units off the same parent set, each containing a `data_feed` message with the same `feed_name`/value, before either stabilizes. Both units will have identical `level` (level = 1 + max(parent levels)) and, being unconfirmed siblings, the same `latest_included_mc_index`. When any AA whose definition references `in data feed` on that oracle (querying unstable data) is triggered — which happens automatically as part of consensus-critical AA execution under `handleTrigger`/`handleAATriggers` — the thrown exception propagates uncaught.

Because AA processing runs synchronously inside the node's core write path (mutex-protected `db` transaction), the exception is not caught by any `ifError`-style callback and surfaces as a Node.js uncaught exception. `network.js` installs a global handler that deliberately re-throws to crash the process: [4](#0-3) 

Since AA execution is deterministic and must be replayed identically by every full node validating/relaying the same unit, this crash is not confined to a single node — every full node that processes the triggering unit (and any node that later tries to replay/validate it) hits the same unhandled exception, unable to confirm new units built on top of that AA trigger.

### Impact Explanation
This is analogous to the CVE's classification: missing input validation on attacker-supplied data leads to an unhandled fault causing a Denial of Service. Here, the "crafted BGP UPDATE" is replaced by two ordinary, unprivileged unit postings (data-feed messages) that create a tie the code doesn't expect. The resulting uncaught exception crashes the node process. Because AA state transitions must be deterministic and are replayed by all full nodes that need to validate the AA's response unit, this can stall or crash multiple/most full nodes processing the same DAG region, matching the "network unable to confirm new units" impact bucket.

### Likelihood Explanation
Likelihood is high: no special privileges are required — only the ability to post two ordinary units (with `data_feed` messages) from an address, whose posts happen to be siblings (share the same parent set) and encode the same feed value, targeted at an AA that reads that oracle's feed while unstable (`in data feed` op is a common, documented oscript primitive). Arranging two sibling units with the same parents and the same level is straightforward and entirely under attacker control (post both without letting either become a parent of the other).

### Recommendation
In `data_feeds.js`, replace the `throw Error(...)` fallback in the `arrCandidates.sort()` comparator with a deterministic, total tie-breaker (e.g., compare by `unit` hash lexicographically) instead of throwing, for all cases — not just `bIncludeAllUnstable`. Alternatively, treat a genuine tie the same way as the `'abort'`/`bAbortedBecauseOfSeveral` path (returning "ambiguous"/no-value result) so that malformed or ambiguous oracle data degrades gracefully instead of crashing the node.

### Proof of Concept
1. Attacker controls address `X`, which is referenced as an oracle (`in data feed`) by some AA `A` that is triggered on ordinary payments.
2. Attacker crafts two units `U1` and `U2`, both children of the same parent set (siblings), each authored by `X`, each containing a `data_feed` message with the same `feed_name` (e.g. `"price"`) and the same value (e.g. `100`).
3. Attacker broadcasts `U1` and `U2` so both remain unstable simultaneously (same `latest_included_mc_index` and identical DAG `level`).
4. Attacker (or anyone) triggers AA `A` with a payment; `A`'s formula evaluates `in data feed[[oracles=X, feed_name="price", ...]]` (or `data_feed[[...]]`) while `U1`/`U2` are still unstable.
5. `readDataFeedValue()` builds `arrCandidates` with two tied entries and executes the `sort()` comparator, hitting `throw Error("can't sort candidates ...")`.
6. The exception is uncaught within the AA trigger processing pipeline, and `network.js`'s `process.on('uncaughtException', ...)` handler re-throws it, crashing the node process — reproducible deterministically on every full node that processes the same trigger unit.

### Citations

**File:** data_feeds.js (L250-267)
```javascript
		else if (arrCandidates.length > 1) {
			if (ifseveral === 'abort') {
				objResult.bAbortedBecauseOfSeveral = true;
				return handleResult(objResult);
			}
			arrCandidates.sort(function (a, b) {
				if (a.latest_included_mc_index < b.latest_included_mc_index)
					return -1;
				if (a.latest_included_mc_index > b.latest_included_mc_index)
					return 1;
				if (a.level < b.level)
					return -1;
				if (a.level > b.level)
					return 1;
				if (bIncludeAllUnstable) // still ambiguous, sort randomly (it's OK outside AAs)
					return 1;
				throw Error("can't sort candidates "+a+" and "+b);
			});
```

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

**File:** network.js (L4530-4543)
```javascript
process.on('uncaughtException', (err) => {
	console.log('Uncaught exception:', err);
	console.error('Uncaught exception:', err);
	if (!conf.bLight) {
		let hosts = [...Object.keys(messagesInWork), ...Object.keys(requestsInWork)];
		if (currentJointHost)
			hosts.push(currentJointHost);
		console.log('Clients with pending requests/messages at the time of uncaught exception:', hosts);
		const fs = require('fs');
		const app_data_dir = require('./desktop_app.js').getAppDataDir();
		fs.writeFileSync(`${app_data_dir}/uncaught_exception_clients.txt`, hosts.concat(Object.keys(assocBlockedPeers)).join('\n'), 'utf8');
	}
	throw err; // crash the process to avoid ending up in an inconsistent state
});
```
