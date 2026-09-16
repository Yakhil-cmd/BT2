### Title
`from_hub` mutex can be left permanently locked if a message-handler code path fails to invoke either `ifOk` or `ifError`, blocking all further hub messages (signing, private payments, contract updates) - ([File: wallet.js])

### Summary
`handleMessageFromHub()` serializes *all* incoming hub messages for a device behind a single `mutex.lock(["from_hub"], ...)` and explicitly documents the precondition for correctness: *"one of callbacks MUST be called, otherwise the mutex will stay locked."* This is structurally the same bug class as the reported `frontrunLock` issue: a global gate that is expected to be released by a specific callback path, with no timeout, watchdog, or fallback unlock. If any message-handling branch inside `doHandle()` returns without calling `callbacks.ifOk()` or `callbacks.ifError()` (e.g., an unexpected code path, a promise that neither resolves error nor success, or a future refactor that adds a new early `return` without a corresponding callback call), the `"from_hub"` lock is held forever.

### Finding Description
The lock is acquired once per hub message and is meant to be released exactly once via the wrapped `callbacks.ifOk`/`callbacks.ifError`: [1](#0-0) 

Everything inside `doHandle()` is a giant `switch(subject)` with dozens of branches — pairing, signing (`sign`), `private_payments`, `arbiter_contract_*`, `prosaic_contract_*`, etc. — each of which is required to eventually call one of the two callbacks: [2](#0-1) [3](#0-2) 

Unlike the `mutex.lock` implementation itself, which only detects "possible deadlocks" via a disabled `setInterval(checkForDeadlocks, 1000)` (the call is commented out): [4](#0-3) 

there is no runtime safeguard that unlocks `"from_hub"` if a callback is never invoked. The only protection against a thrown exception is the `try/catch` around `doHandle()`, which converts synchronous exceptions into `ifError`: [5](#0-4) 
but this catch does **not** protect asynchronous code paths (e.g. inside `db.query`, `arbiter_contract.getByHash`, `eventBus.once` callbacks, or `async`/`await` blocks) where a missing call to `callbacks.ifOk()`/`callbacks.ifError()` on some branch would silently leave the lock held with no exception to catch, e.g. the deeply nested async branches of `arbiter_contract_update` and `arbiter_dispute_request`: [6](#0-5) [7](#0-6) 

Because the mutex has no timeout, once locked without a matching unlock, every subsequent message from the paired hub/device — including signing requests/responses needed to spend funds, `private_payments` (needed to receive and later spend private-asset outputs), and arbiter contract state transitions — is queued forever and never processed: [8](#0-7) 

This directly parallels the reported `frontrunLock`/VRF issue: a lock is set up assuming a callback will always fire, but there is no mechanism to recover if that assumption is violated.

### Impact Explanation
A stuck `"from_hub"` mutex halts the wallet's device-message pipeline entirely. Practically this can freeze:
- Multi-device/multisig **signing** flows (`sign`, `signature` cases), preventing outputs from ever being spendable via cosigning.
- **`private_payments`** handling, preventing receipt (and thus future spending) of private asset chains sent to this device.
- Arbiter/prosaic contract state transitions that gate fund release.

Since ocore wallets rely on this device-messaging channel for cosigning and private payment delivery, a permanently locked mutex constitutes a denial of core wallet functionality — consistent with the "AA fund loss or freezing" / "unable to confirm/process legitimate messages" impact class described in the validation criteria.

### Likelihood Explanation
Likelihood is **moderate, not confirmed**: I was not able to find, within the code actually reviewed, a concrete branch that both (a) is reachable from an unprivileged paired device and (b) definitively omits a callback call on every exit path — the reviewed cases (`sign`, `private_payments`, `arbiter_contract_*`, `prosaic_contract_*`) all appear to call `ifOk`/`ifError` on the paths inspected. However:
- The switch statement is large (dozens of branches, deeply nested async control flow across multiple modules: `arbiter_contract.js`, `prosaic_contract.js`, `walletDefinedByAddresses.js`, `device.js`), and the code's own comment ("one of callbacks MUST be called, otherwise the mutex will stay locked") signals that this invariant is manually maintained rather than structurally enforced — a single missed `return callbacks.ifError(...)`/added early-return in any future branch (or in a called sub-module like `arbiter_contract.setField`, `device.handlePairingMessage`, etc., whose full callback-completeness I could not fully verify) reintroduces the exact bug class described in the report.
- There is no lock timeout/expiry as a defense-in-depth measure, so any single occurrence is permanent, unlike a transient network stall.

Given the size/index limitations of this review, I could not exhaustively trace every nested async callback path (e.g., inside `arbiter_contract.js`, `prosaic_contract.js`, `walletDefinedByAddresses.js`) to prove a specific always-reachable missing-callback trigger; this should be verified with a full audit of those modules or via fuzzing malformed/edge-case hub message bodies.

### Recommendation
- Add a lock-acquisition timestamp/timeout to the `"from_hub"` mutex key (or a global watchdog similar to `checkForDeadlocks`, but enabled) that force-releases and logs if the lock is held beyond a sane threshold (e.g., 30–60s), rather than leaving `checkForDeadlocks` disabled.
- Refactor `handleMessageFromHub`/`doHandle` so the unlock is guaranteed via `finally`-style wrapping (e.g., wrap every switch branch's terminal callback invocation in a single guaranteed-once release, or use `Promise.allSettled`/`async` control flow with a single top-level `finally`) instead of relying on each of ~25 case branches to manually call back correctly.
- Add an assertion/audit test that iterates all `subject` values with malformed bodies and confirms exactly one callback fires for every code path, to catch any silently-missing callback regressions.

### Proof of Concept
Not independently reproduced end-to-end (no fully confirmed missing-callback branch was identified in this review). Conceptually: a hub delivers a crafted `handle_message_from_hub` event for a device with a `subject`/`body` combination that reaches a nested async callback (e.g., deep inside `arbiter_contract_update`'s multi-level `db.query`/`getByHash` chain) where an exception or unexpected state is thrown/returned without invoking `callbacks.ifError`. This permanently holds `mutex.lock(["from_hub"])`, after which no further `sign`, `signature`, or `private_payments` messages from that hub are ever processed for the affected device, freezing cosigning and private-payment reception indefinitely. Confirming this requires deeper tracing into `arbiter_contract.js`, `prosaic_contract.js`, and `walletDefinedByAddresses.js` callback completeness, which was not fully available within this review's scope.

### Citations

**File:** wallet.js (L63-81)
```javascript
// one of callbacks MUST be called, otherwise the mutex will stay locked
function handleMessageFromHub(ws, json, device_pubkey, bIndirectCorrespondent, callbacks){
	if (isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000))
		return callbacks.ifError("message from hub is too deeply nested or has too many nodes");

	// serialize all messages from hub
	mutex.lock(["from_hub"], function(unlock){
		var oldcb = callbacks;
		callbacks = {
			ifOk: function(){oldcb.ifOk(); unlock();},
			ifError: function(err){oldcb.ifError(err); unlock();}
		};
		try {
			doHandle();
		}
		catch (e) {
			callbacks.ifError("exception in handleMessageFromHub: " + e.toString());
		}
	});
```

**File:** wallet.js (L96-99)
```javascript
		switch (subject){
			case "pairing":
				device.handlePairingMessage(json, device_pubkey, callbacks);
				break;
```

**File:** wallet.js (L420-424)
```javascript
			case 'private_payments':
				if (conf.bIgnorePrivatePayments)
					return callbacks.ifError("private payments are ignored");
				handlePrivatePaymentChains(ws, body, from_address, callbacks);
				break;
```

**File:** wallet.js (L681-744)
```javascript
			case 'arbiter_contract_update':
				if (!ValidationUtils.isNonemptyString(body.hash))
					return callbacks.ifError("no contract hash");
				arbiter_contract.getByHash(body.hash, function(objContract){
					if (!objContract)
						return callbacks.ifError("wrong contract hash");
					db.query("SELECT 1 FROM wallet_signing_paths JOIN my_addresses USING(wallet) WHERE device_address=? AND address=?", [from_address, objContract.my_address], function(rows) {
						const from_cosigner = (rows.length && objContract.me_is_cosigner);
						if (from_address !== objContract.peer_device_address && !from_cosigner && !(from_address === objContract.arbstore_device_address && objContract.status === 'in_appeal' && body.field === 'status'))
							return callbacks.ifError("not an owner");
						if (body.field === "status") {
							var isOK = false;
							switch (objContract.status) {
								case "pending":
									if (body.value === "revoked" || from_cosigner && ["accepted", "declined"].includes(body.value))
										isOK = true;
									break;
								case "paid":
									if (body.value === "in_dispute")
										isOK = true;
									break;
								case "dispute_resolved":
									if (body.value === "in_appeal" && from_cosigner)
										isOK = true;
									break;
								case "in_appeal":
									if (objContract.arbstore_device_address === from_address && (body.value === 'appeal_approved' || body.value === 'appeal_declined'))
										isOK = true;
									break;
							}
							if (!isOK)
								return callbacks.ifError("wrong status for contract supplied");
						} else 
						if (body.field === "unit") {
							if (objContract.status !== "accepted")
								return callbacks.ifError("contract was not accepted");
							if (objContract.unit)
								return callbacks.ifError("unit was already provided for this contract");
							if (!ValidationUtils.isValidBase64(body.value, constants.HASH_LENGTH))
								return callbacks.ifError("invalid unit hash provided");
							if (!objContract.shared_address)
								return callbacks.ifError("unit received while shared_address is not set yet");
							arbiter_contract.handleReceivedSigningUnit(objContract, body.value, from_cosigner);
							return callbacks.ifOk();
						} else
						if (body.field === "shared_address") {
							if (objContract.status !== "accepted")
								return callbacks.ifError("contract was not accepted");
							if (objContract.shared_address)
								return callbacks.ifError("shared_address was already provided for this contract");
							if (!ValidationUtils.isValidAddress(body.value))
								return callbacks.ifError("invalid address provided");
							arbiter_contract.handleReceivedSharedAddress(objContract.hash, body.value, from_cosigner);
							return callbacks.ifOk();
						} else {
							return callbacks.ifError("wrong field");
						}
						arbiter_contract.setField(objContract.hash, body.field, body.value, function(objContract) {
							eventBus.emit("arbiter_contract_update", objContract, body.field, body.value);
							callbacks.ifOk();
						}, from_cosigner);
					});
				});
				break;
```

**File:** wallet.js (L747-862)
```javascript
			case 'arbiter_dispute_request':
				if (!body.contract_hash || !body.my_address || !body.peer_address || body.me_is_payer === undefined || !body.my_pairing_code || !body.peer_pairing_code
					|| !body.encrypted_contract || !body.unit || !body.amount || body.asset === undefined || !body.arbiter_address || !body.service_fee_asset)
					return callbacks.ifError("wrong dispute request");
				if (!ValidationUtils.isNonemptyString(body.contract_hash))
					return callbacks.ifError("bad contract hash");
				if (!ValidationUtils.isStringOfLength(body.unit, constants.HASH_LENGTH))
					return callbacks.ifError("bad unit in dispute request");
				if (body.service_fee_asset !== 'base' && !ValidationUtils.isValidBase64(body.service_fee_asset, constants.HASH_LENGTH))
					return callbacks.ifError("bad service_fee_asset in dispute request");
				if (![body.my_address, body.peer_address, body.arbiter_address, body.shared_address].every(ValidationUtils.isValidAddress))
					return callbacks.ifError("bad addresses in dispute request");
				try {
					var contractContent = device.decryptPackage(body.encrypted_contract);
				}
				catch (e) {
					return callbacks.ifError("failed to decrypt contract content: " + e);
				}
				if (!contractContent || !contractContent.creation_date || !contractContent.title || !contractContent.text)
					return callbacks.ifError("wrong contract content");
				var expectedContractHash = arbiter_contract.getHash({
					title: contractContent.title,
					text: contractContent.text,
					my_address: body.my_address,
					peer_address: body.peer_address,
					creation_date: contractContent.creation_date,
					my_party_name: contractContent.plaintiff_party_name,
					peer_party_name: contractContent.respondent_party_name,
					me_is_payer: body.me_is_payer,
					arbiter_address: body.arbiter_address,
					amount: body.amount,
					asset: body.asset
				});
				if (body.contract_hash !== expectedContractHash)
					return callbacks.ifError("wrong contract hash");
				const requestUnit = conf.bLight
					? (onDone) => network.requestHistoryFor([body.unit], [], err => {
						if (!err) return onDone();
						console.log("failed to load signing unit " + body.unit + " for dispute request, will try again in 30s");
						setTimeout(() => requestUnit(onDone), 30000);
					})
					: (onDone) => onDone();
				requestUnit(async () => {
					const objUnit = await storage.readUnit(body.unit);
					if (!objUnit)
						return callbacks.ifError("signing unit not found");
					const dataMessage = objUnit.messages.find(msg => msg.app === 'data');
					if (!dataMessage)
						return callbacks.ifError("no data message in signing unit");
					const { payload } = dataMessage;
					const contacts_hash = arbiter_contract.getContactsHash({
						me_is_payer: body.me_is_payer,
						my_pairing_code: body.my_pairing_code,
						peer_pairing_code: body.peer_pairing_code,
						my_contact_info: contractContent.my_contact_info,
						peer_contact_info: contractContent.peer_contact_info,
					});
					if (payload.contacts_hash !== contacts_hash)
						return callbacks.ifError("contacts hash doesn't match the signing unit");
					if (payload.contract_text_hash !== body.contract_hash)
						return callbacks.ifError("contract hash doesn't match the signing unit");
					if (payload.arbiter !== body.arbiter_address)
						return callbacks.ifError("arbiter address doesn't match the signing unit");

					const author = objUnit.authors.find(author => author.address === body.shared_address);
					if (!author)
						return callbacks.ifError("shared address author not found in signing unit");
					const signing_paths = Object.keys(author.authentifiers);
					const isMutuallySigned = signing_paths.find(p => p.startsWith('r.0.0')) && signing_paths.find(p => p.startsWith('r.0.1'));
					if (!isMutuallySigned)
						return callbacks.ifError(`signing unit ${body.unit} is not mutually signed, authentifiers: ${JSON.stringify(author.authentifiers)}`);
					const definition = author.definition;
					if (!definition)
						return callbacks.ifError("no definition for shared address author in signing unit");
					let offeror_address, acceptor_address;
					try {
						const mutualPart = definition[1][0][1];
						offeror_address = mutualPart[0][1];
						acceptor_address = mutualPart[1][1];
					} catch (e) {
						return callbacks.ifError("unexpected definition structure in signing unit");
					}
					if (typeof offeror_address !== 'string' || typeof acceptor_address !== 'string')
						return callbacks.ifError("unexpected definition structure in signing unit");
					const bCorrectParties =
						offeror_address === body.my_address && acceptor_address === body.peer_address
						|| offeror_address === body.peer_address && acceptor_address === body.my_address;
					if (!bCorrectParties)
						return callbacks.ifError("offeror and acceptor addresses in signing unit don't match the dispute request");

					const rows = await db.query("SELECT 1 FROM my_addresses WHERE address=?", [body.arbiter_address]);
					if (rows.length === 0)
						return callbacks.ifError("the arbiter is not me");

					// rejection is ok, the message will not be deleted from the hub
					const { device_address } = await arbiters.getArbstoreInfo(body.arbiter_address);
					if (device_address !== from_address)
						return callbacks.ifError("you are not my arbstore");

					body.contract_content = contractContent;
					body.arbstore_device_address = from_address;
					arbiter_contract.insertDispute(body, function(res) {
						if (res.affectedRows == 0) {
							return callbacks.ifError("can't insert dispute request into db");
						}
						var objDispute = {
							contract_hash: body.contract_hash,
							title: contractContent.title,
							service_fee_asset: body.service_fee_asset
						};
						var chat_message = "(arbiter-dispute:" + Buffer.from(JSON.stringify(objDispute), 'utf8').toString('base64') + ")";
						eventBus.emit("text", from_address, chat_message, ++message_counter);
						callbacks.ifOk();
					});
				});
				break;
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
