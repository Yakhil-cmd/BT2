### Title
Indefinite lock of `c-ADDRESS` mutex during multisig cosigner signing can permanently freeze an address's ability to compose new transactions - (File: composer.js)

### Summary
`composeJoint()` in `composer.js` acquires a mutex on keys `'c-'+from_address` for every paying address and holds it until either an error path calls `handleError()` or the final signing callback resolves via `callbacks.ifOk(..., unlock_callback)`. When a payment requires signatures from a multisig cosigner reachable only via a paired device, the code waits on a one-time event (`eventBus.once("signature-"+device_address+...)`) that fires only if the cosigner device responds. If that paired device never responds (refuses to send a `"signature"` or `"sign"`-refusal message), the `async.each` callback chain in the signing step never completes, `handleError`/`callbacks.ifOk` is never invoked, and the `'c-'+address` lock is never released. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Finding Description
`composeJoint()` locks the composing address(es) at the very start of the function via `mutex.lock(arrFromAddresses.map(a => 'c-'+a), ...)`, storing the `unlock` callback in `unlock_callback`, explicitly to "keep c-ADDRESS lock to avoid creating accidental doublespends" while multisig signing, which "may take very very long", is performed after the DB transaction is committed and released. [5](#0-4) [6](#0-5) 

For multisig/shared addresses whose cosigner key lives on another device, the `signer.sign` implementation in `wallet.js`'s `getSigner()` sends a `"sign"` request to the remote device and registers a **one-time** event listener keyed by `device_address/address/signing_path/hash`, calling `handleSignature` only once that event fires: [7](#0-6) 

There is no timeout on this wait. If the cosigner (a paired device counterparty) never sends back a `"signature"` message (e.g., stays silent instead of explicitly sending `'[refused]'`), the `async.each`/`async.series` chain inside `composeJoint`'s signing step (lines 554-599) never reaches its final callback, so neither `handleError(err)` nor `callbacks.ifOk(objJoint, assocPrivatePayloads, unlock_callback)` is ever called. Consequently the `mutex.js` lock entry for key `'c-'+address` (pushed in `exec()` and only removed by the matching `unlock()` call) is never released: [8](#0-7) 

Because `mutex.lock` queues subsequent jobs requesting any of the same keys (`isAnyOfKeysLocked` check in `lock()`), every future attempt to compose a payment or sign anything from the same address is queued indefinitely and never executes, since `handleQueue()` is only invoked from inside `unlock()`. [9](#0-8) [10](#0-9) 

The `checkForDeadlocks()` safety-net that would `throw Error("possible deadlock ...")` after 30 seconds of queuing is explicitly commented out (`//setInterval(checkForDeadlocks, 1000);`), so there is no automatic detection or recovery mechanism in production: [11](#0-10) 

### Impact Explanation
Any shared/multisig address configured with a cosigner device controlled by a counterparty can be permanently frozen by that counterparty simply refusing to answer signing requests (rather than sending `'[refused]'`, which would resolve the chain via `cb3('one of the cosigners refused to sign')`). Once one composeJoint call is stuck waiting on a signature that never arrives, the address-scoped `'c-'+address` mutex is held forever, and the wallet (or any AA/asset flow relying on that address, e.g. arbiter contracts, shared-address deposits in `arbiter_contract.js`) can never compose or send another transaction from that address again — a permanent, irrecoverable denial-of-service/fund-freezing condition on the shared address requiring a wallet restart (which resets the in-memory mutex state) to recover.

### Likelihood Explanation
The lock-forever pattern requires only that a counterparty paired-device cosigner on a shared/multisig address simply never responds to a `"sign"` request that was already offered (which the initiator legitimately triggers, e.g., through `arbiter_contract.js`'s `createSharedAddressAndPostUnit` or any `sendMultiPayment` involving multiple signing devices). No special privileges beyond being a paired cosigner on the shared address are required, and non-response is trivial to achieve (simply not sending back the `"signature"` message). The only mitigating factor is that it affects shared/multisig addresses (not all addresses), but such addresses are a standard, supported feature of the wallet (`wallet_defined_by_addresses.js`, `arbiter_contract.js`).

### Recommendation
1. Add a timeout to `signer.sign` / the `eventBus.once("signature-...")` wait in `wallet.js`, so that a non-responding cosigner results in `handleSignature(err)` rather than an unbounded wait.
2. In `composer.js`, wrap the signing `async.each` in `composeJoint` with a timeout that calls `handleError()` to release the `'c-'+address` lock if signing does not complete within a bounded time.
3. Re-enable and tune `checkForDeadlocks()` in `mutex.js` (or an equivalent monitoring mechanism) so that stuck locks/queued jobs are detected and can trigger recovery instead of silently hanging forever.

### Proof of Concept
1. Configure a shared/multisig address with a cosigner reachable only via a paired device (as in `arbiter_contract.js`'s `createSharedAddressAndPostUnit`, or a standard multisig `sendMultiPayment`).
2. Initiate a payment from that shared address; `composeJoint` locks `'c-'+shared_address` (composer.js:289) and, after committing parents, reaches the signing stage (composer.js:554-599).
3. `signer.sign` (wallet.js:2030-2041) sends a `"sign"` offer to the cosigner device and registers a one-time listener for the `"signature-..."` event.
4. The cosigner device (attacker-controlled) receives the `"sign"` message but never replies with a `"signature"` message (does not call `sendSignature`).
5. The `async.each`/`async.series` chain in `composeJoint` never completes; `unlock_callback` is never invoked; the `'c-'+shared_address` lock entry in `mutex.js`'s `arrLockedKeyArrays` remains forever.
6. Any subsequent call to `composeJoint`/`sendMultiPayment` from the same shared address is queued in `mutex.js`'s `arrQueuedJobs` and never runs, since `handleQueue()` fires only on `unlock()`, permanently freezing the address's ability to transact.

### Citations

**File:** composer.js (L269-293)
```javascript
	var total_input;
	var last_ball_mci;
	let vote_count_fee = 0;
	var unlock_callback;
	var conn;
	var lightProps;
	
	var handleError = function(err){
		//profiler.stop('compose');
		unlock_callback();
		if (typeof err === "object"){
			if (err.error_code === "NOT_ENOUGH_FUNDS")
				return callbacks.ifNotEnoughFunds(err.error);
			throw Error("unknown error code in: "+JSON.stringify(err));
		}
		callbacks.ifError(err);
	};
	
	async.series([
		function(cb){ // lock
			mutex.lock(arrFromAddresses.map(function(from_address){ return 'c-'+from_address; }), function(unlock){
				unlock_callback = unlock;
				cb();
			});
		},
```

**File:** composer.js (L530-536)
```javascript
		// we close the transaction and release the connection before signing as multisig signing may take very very long
		// however we still keep c-ADDRESS lock to avoid creating accidental doublespends
		conn.query(err ? "ROLLBACK" : "COMMIT", function(){
			conn.release();
			if (err)
				return handleError(err);
			
```

**File:** composer.js (L554-599)
```javascript
			async.each(
				authors_for_signing,
				function(author, cb2){
					var address = author.address;
					async.each( // different keys sign in parallel (if multisig)
						Object.keys(author.authentifiers),
						function(path, cb3){
							if (signer.sign){
								signer.sign(objUnit, assocPrivatePayloads, address, path, function(err, signature){
									if (err)
										return cb3(err);
									// it can't be accidentally confused with real signature as there are no [ and ] in base64 alphabet
									if (signature === '[refused]')
										return cb3('one of the cosigners refused to sign');
									author.authentifiers[path] = signature;
									cb3();
								});
							}
							else{
								signer.readPrivateKey(address, path, function(err, privKey){
									if (err)
										return cb3(err);
									author.authentifiers[path] = ecdsaSig.sign(text_to_sign, privKey);
									cb3();
								});
							}
						},
						function(err){
							cb2(err);
						}
					);
				},
				function(err){
					if (err)
						return handleError(err);
					objUnit.unit = objectHash.getUnitHash(objUnit);
					if (bGenesis)
						objJoint.ball = objectHash.getBallHash(objUnit.unit);
					console.log(require('util').inspect(objJoint, {depth:null}));
				//	objJoint.unit.timestamp = Math.round(Date.now()/1000); // light clients need timestamp
					if (Object.keys(assocPrivatePayloads).length === 0)
						assocPrivatePayloads = null;
					//profiler.stop('compose');
					callbacks.ifOk(objJoint, assocPrivatePayloads, unlock_callback);
				}
			);
```

**File:** wallet.js (L2016-2042)
```javascript
		sign: function (objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature) {
			var buf_to_sign = objectHash.getUnitHashToSign(objUnsignedUnit);
			findAddress(address, signing_path, {
				ifError: function (err) {
					throw Error(err);
				},
				ifUnknownAddress: function (err) {
					throw Error("unknown address " + address + " at " + signing_path);
				},
				ifLocal: function (objAddress) {
					signWithLocalPrivateKey(objAddress.wallet, objAddress.account, objAddress.is_change, objAddress.address_index, buf_to_sign, function (sig) {
						handleSignature(null, sig);
					});
				},
				ifRemote: function (device_address) {
					// we'll receive this event after the peer signs
					eventBus.once("signature-" + device_address + "-" + address + "-" + signing_path + "-" + buf_to_sign.toString("base64"), function (sig) {
						var key = device_address + address + buf_to_sign.toString("base64");
						handleSignature(null, sig);
						if (responses[key]) // it's a cache to not emit multiple similar events for one unit (when we have same address in multiple paths)
							return;
						responses[key] = true;
						if (sig === '[refused]')
							eventBus.emit('refused_to_sign', device_address);
					});
					walletGeneral.sendOfferToSign(device_address, address, signing_path, objUnsignedUnit, assocPrivatePayloads);

```

**File:** mutex.js (L43-59)
```javascript
function exec(arrKeys, proc, next_proc){
	arrLockedKeyArrays.push(arrKeys);
	console.log("lock acquired", arrKeys);
	var bLocked = true;
	proc(function unlock(unlock_msg) {
		if (!bLocked)
			throw Error("double unlock?");
		if (unlock_msg)
			console.log(unlock_msg);
		bLocked = false;
		release(arrKeys);
		console.log("lock released", arrKeys);
		if (next_proc)
			next_proc.apply(next_proc, arguments);
		handleQueue();
	});
}
```

**File:** mutex.js (L61-73)
```javascript
function handleQueue(){
	console.log("handleQueue "+arrQueuedJobs.length+" items");
	for (var i=0; i<arrQueuedJobs.length; i++){
		var job = arrQueuedJobs[i];
		if (isAnyOfKeysLocked(job.arrKeys))
			continue;
		arrQueuedJobs.splice(i, 1); // do it before exec as exec can trigger another job added, another lock unlocked, another handleQueue called
		console.log("starting job held by keys", job.arrKeys);
		exec(job.arrKeys, job.proc, job.next_proc);
		i--; // we've just removed one item
	}
	console.log("handleQueue done "+arrQueuedJobs.length+" items");
}
```

**File:** mutex.js (L75-86)
```javascript
function lock(arrKeys, proc, next_proc){
	if (arguments.length === 1)
		return new Promise(resolve => lock(arrKeys, resolve));
	if (typeof arrKeys === 'string')
		arrKeys = [arrKeys];
	if (isAnyOfKeysLocked(arrKeys)){
		console.log("queuing job held by keys", arrKeys);
		arrQueuedJobs.push({arrKeys: arrKeys, proc: proc, next_proc: next_proc, ts:Date.now()});
	}
	else
		exec(arrKeys, proc, next_proc);
}
```

**File:** mutex.js (L107-116)
```javascript
function checkForDeadlocks(){
	for (var i=0; i<arrQueuedJobs.length; i++){
		var job = arrQueuedJobs[i];
		if (Date.now() - job.ts > 30*1000)
			throw Error("possible deadlock on job "+require('util').inspect(job)+",\nproc:"+job.proc.toString()+" \nall jobs: "+require('util').inspect(arrQueuedJobs, {depth: null}));
	}
}

// long running locks are normal in multisig scenarios
//setInterval(checkForDeadlocks, 1000);
```
