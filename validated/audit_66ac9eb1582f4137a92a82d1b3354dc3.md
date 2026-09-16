## Analysis

The CVE describes a case where an external operation (getting a timestamp from PD) can fail in a way that produces an unhandled/fatal error and crashes the node process — a pure availability bug triggered by ordinary, low-privilege usage.

The closest reachable analog in `ocore--010` is in the `in_data_feed()` oscript function's backing implementation, `dataFeedByAddressExists()`, in [1](#0-0) . This function is invoked by any AA whose bytecode calls `in_data_feed(...)`, which is itself triggerable by any unprivileged unit poster who sends a trigger unit to that AA — exactly the class of "AA trigger sender" callers this scan is scoped to.

### Title
Unhandled double-fire of stream `'end'` handler in `dataFeedByAddressExists()` crashes the node - (File: `data_feeds.js`)

### Summary
`dataFeedByAddressExists()`, used to implement the `in_data_feed()` oscript primitive, opens a RocksDB key-stream and, for non-equality relations, calls `stream.destroy()` followed by a manual `onEnd()` invocation as soon as a matching record is found [2](#0-1) . The `onEnd()` function throws unconditionally if it is ever called a second time: `if (bOnEndCalled) throw Error("second call of onEnd");` [3](#0-2) . Because `onEnd` is also registered as the stream's `'end'` listener (`stream.on('data', handleData).on('end', onEnd)` [4](#0-3) ), if the underlying stream emits `'end'` after (or racing with) the manual `destroy()`+`onEnd()` call — a known Node.js Readable-stream footgun when data is already buffered before `destroy()` takes effect — `onEnd()` runs twice and throws inside an asynchronous stream event callback, which is unrecoverable by any caller.

### Finding Description
`in_data_feed()` is reachable from oscript/AA evaluation via `formula/evaluation.js`, which calls `dataFeeds.dataFeedExists(...)` for the `'in_data_feed'` case; `dataFeedExists()` in turn iterates over oracle addresses and calls `dataFeedByAddressExists()` for each one [5](#0-4) . For any relation other than `'='` (e.g. `>`, `<`, `>=`, `<=`), `dataFeedByAddressExists()` uses a streaming scan and terminates early on the first match by calling `stream.destroy(); onEnd();` directly inside the `'data'` handler [6](#0-5) . Any AA logic that calls `in_data_feed(oracle, feed_name, value, '>' , ...)` or similar non-equality comparisons exercises this exact code path on every trigger.

Any throw raised asynchronously inside a stream event handler is an uncaught exception at the process level; it is not caught by the `validation.validate()`/`aa_composer` callback chains that invoke oscript evaluation. The global handler in `network.js` explicitly re-throws such exceptions to crash the whole process: `process.on('uncaughtException', ... ); throw err; // crash the process to avoid ending up in an inconsistent state` [7](#0-6) .

### Impact Explanation
A single unprivileged user can post a trigger unit to any AA that uses `in_data_feed()` with a non-equality relation against oracle data. If the race between `stream.destroy()` and the underlying stream's own `'end'` emission is hit (a realistic outcome when the LevelDB/RocksDB read stream has already buffered further records before `destroy()` takes effect), the node throws inside the stream callback and crashes via the deliberate `throw err` in the global `uncaughtException` handler. This matches the "network unable to confirm new units" impact bucket: crashing full/witness nodes that host or process such an AA halts unit processing until manual restart, and can be repeated by re-triggering the same AA.

### Likelihood Explanation
`in_data_feed()` with a non-`'='` relation is a normal, documented oscript feature used by real AAs (price-feed thresholds, oracle comparisons), so many existing/deployed AAs already exercise this exact code path on every incoming trigger. The trigger cost to the attacker is a single ordinary unit; no special privileges, witness status, or network position are required — only knowledge of an AA address that uses this construct.

### Recommendation
Do not treat a stream `'end'` after a manual `destroy()` as a fatal condition: guard the manual `onEnd()` invocation and the `'end'` listener with an idempotent flag that simply ignores (rather than throws on) the second invocation, e.g. change the `onEnd` guard to `if (bOnEndCalled) return;` instead of throwing, and ensure `handleResult` is only ever invoked once.

### Proof of Concept
1. Deploy (or identify an existing) AA whose bytecode contains an expression such as `in_data_feed({oracles: "...", feed_name: "PRICE", feed_value: '>' 100})`.
2. Have any user (unprivileged) send a trigger unit to that AA's address.
3. During AA evaluation, `dataFeedByAddressExists()` opens a RocksDB key-stream for the `'>'` relation; on the first matching key it calls `stream.destroy()` then `onEnd()` synchronously inside the `'data'` handler [8](#0-7) .
4. If the stream also fires its own `'end'` event (buffered before `destroy()` propagated), `onEnd()` is invoked a second time and throws `Error("second call of onEnd")` [9](#0-8) , which is uncaught and crashes the node process via the `uncaughtException` handler in `network.js`.

### Citations

**File:** data_feeds.js (L98-108)
```javascript
	async.eachSeries(
		arrAddresses,
		function(address, cb){
			dataFeedByAddressExists(address, feed_name, relation, value, min_mci, max_mci, cb);
		},
		function(bFound){
			console.log('data feed by '+arrAddresses+' '+feed_name+relation+value+': '+bFound+', df took '+(Date.now()-start_time)+'ms');
			handleResult(!!bFound);
		}
	);
}
```

**File:** data_feeds.js (L110-202)
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
	var count = 0;
	var count_before_found = 0;
	var handleData;
	if (relation === '=')
		handleData = function(data){
			count++;
			count_before_found++;
			bFound = true;
		};
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
	var bOnEndCalled = false;
	function onEnd(){
		if (bOnEndCalled)
			throw Error("second call of onEnd");
		bOnEndCalled = true;
		console.log('data feed by '+address+' '+feed_name+relation+value+': '+bFound+', '+count_before_found+' / '+count+' records inspected');
		handleResult(bFound);
	}
	var stream = kvstore.createKeyStream(options);
	stream.on('data', handleData)
	.on('end', onEnd)
	.on('error', function(error){
		throw Error('error from data stream: '+error);
	});
}
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
