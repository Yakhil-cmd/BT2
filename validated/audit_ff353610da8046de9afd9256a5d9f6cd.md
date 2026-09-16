### Title
Memory leak via unbounded `arbiter_contract_update` listener accumulation from repeated payments to a shared arbiter-contract address - ([File: arbiter_contract.js])

### Summary
The `new_my_transactions` handler in `arbiter_contract.js` registers a new, uniquely-named `eventBus.on('arbiter_contract_update', retryPaymentCheck)` listener every time it observes a qualifying payment to a contract's `shared_address` while the contract is in the `accepted` state, and only removes that listener when a later `unit`-field update for the same contract hash arrives. A counterparty to an arbiter contract (an unprivileged, reachable actor — the peer of a private/arbiter payment) can repeatedly cause the qualifying-payment condition to fire without ever supplying the `unit` update, causing an unbounded, permanent accumulation of `arbiter_contract_update` listeners, analogous to CVE-2017-9373's memory-consumption DoS from repeatedly triggering a per-event cleanup path that never completes.

### Finding Description
`arbiter_contract.js` listens for `new_my_transactions` to detect contract payments: [1](#0-0) 

Every time the query returns a row whose contract is in status `accepted` (payment observed, but the "unit" update for the mutual signing/finalization message has not arrived yet), the code adds a brand-new closure-scoped listener to the global `eventBus` for the `arbiter_contract_update` event:
```
eventBus.on('arbiter_contract_update', function retryPaymentCheck(objContract, field, value){
    if (objContract.hash === contract.hash && field === 'unit') {
        newtxs(arrNewUnits);
        eventBus.removeListener('arbiter_contract_update', retryPaymentCheck);
    }
});
```
This listener is only unregistered when a matching `unit` field update event for the *same* contract hash is later emitted. Nothing prevents the same qualifying condition (`contract.status === 'accepted'`, payment matches/exceeds `wallet_arbiter_contracts.amount`) from being re-triggered multiple times for the same contract or across many contracts, each addition creating a new closure that is never freed if the corresponding `unit` update never happens.

Reachability: the counterparty of an arbiter contract is an untrusted actor whose own wallet issues `payment` units into the shared address once a contract reaches the `accepted` status (i.e., once shared address is set up but before the mutual signing "unit" message is exchanged). A malicious counterparty in an active/pending arbiter contract negotiation can repeatedly send small excess payments into the shared multisig address (each qualifying via the `HAVING SUM(outputs.amount) >= wallet_arbiter_contracts.amount` condition) while withholding the follow-up "signing unit"/`unit` field message that would trigger listener cleanup. Each such payment is a normal, validly-signed unit reachable through standard DAG unit posting and processed via the `new_my_transactions` wallet event — no special network position, hub, or node privilege is required.

Because `eventBus` is a standard Node `EventEmitter` shared by the whole process, and there is no listener cap enforcement bypass here (the accumulation is via distinct dynamically-created function references, not `MaxListeners` triggering an obvious warning necessarily, though it eventually will), each additional listener retains references to its closure variables (`arrNewUnits`, `contract`), preventing garbage collection and growing heap usage indefinitely as more qualifying payments arrive.

### Impact Explanation
Repeated triggering by a private-payment counterparty causes unbounded memory growth of the victim wallet's process (accumulating never-removed `arbiter_contract_update` listeners and their closures), eventually leading to memory exhaustion / crash or severe slowdown of the wallet node — a denial-of-service condition analogous to the CVE's "memory consumption" impact. This does not directly cause loss of funds but denies availability of the wallet/node, which the analog-scan rules classify at Medium severity when it can render the node/wallet non-functional (unable to process new units/transactions).

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to be an active counterparty in an arbiter contract with the victim (a normal party a victim would enter into for e.g. dispute-arbitrated payments), and to control timing of payments into the shared address while withholding the signing/"unit" update message — both of which are entirely within the counterparty's control since they are the one sending payments and the "unit" message is only sent voluntarily. No cryptographic breaks or race conditions are needed.

### Recommendation
- Deduplicate/guard listener registration, e.g., check whether a `retryPaymentCheck` listener for `contract.hash` is already registered before adding another, or store pending retry state in a keyed map (`assocPendingPaymentChecks[contract.hash]`) instead of adding a new closure to a shared `eventBus` on every qualifying payment.
- Add a TTL/expiry and periodic cleanup for these listeners (similar to the `assocUnitsWaitingForPrunedContent` / `handledChainsCache` patterns elsewhere in the codebase, e.g. [2](#0-1)  and [3](#0-2) ) so an unfulfilled retry listener is eventually removed even if the expected `unit` update never arrives.
- Consider using `eventBus.once` with an explicit unregistration timeout instead of an open-ended `on` listener.

### Proof of Concept
1. Attacker and victim establish an arbiter contract; victim's wallet stores it with `wallet_arbiter_contracts.shared_address` set and `status = 'accepted'` (this state is reached once the shared address is derived, before mutual signing completes) — see `handleReceivedSharedAddress` at [4](#0-3) .
2. Attacker (acting as the payer party or simply the counterparty controlling payments into the shared address) repeatedly issues payment units to `shared_address` for at least `wallet_arbiter_contracts.amount`, each producing a `new_my_transactions` event in the victim's wallet.
3. For every such event, because `contract.status === 'accepted'`, the victim's node executes:
```
eventBus.on('arbiter_contract_update', function retryPaymentCheck(...) {...});
```
adding one more permanent listener (`arbiter_contract.js:837-842`).
4. Attacker never sends the "signing unit" / `data` message that would cause `handleReceivedSigningUnit` to emit `arbiter_contract_update` with `field === 'unit'` (see [5](#0-4) ), so the listeners are never removed.
5. Repeating step 2 many times (e.g., thousands of small qualifying payments across time) causes the `arbiter_contract_update` event's listener array — and the closures it retains — to grow without bound, consuming memory in the victim's node process until it degrades or crashes (OOM), matching the CVE-2017-9373 bug class of unbounded resource accumulation via a repeatable action lacking a corresponding cleanup guarantee.

### Citations

**File:** arbiter_contract.js (L632-658)
```javascript
function handleReceivedSharedAddress(hash, shared_address, from_cosigner, retry_count = 0) {
	console.log(`received shared address ${shared_address} for arbiter contract ${hash} from peer`);
	db.query("SELECT 1 FROM shared_addresses WHERE shared_address=?", [shared_address], function (rows) {
		if (rows.length === 0) {
			if (retry_count >= 10)
				return console.log(`shared address ${shared_address} not found in db after 10 retries, giving up`);
			console.log(`shared address ${shared_address} not yet in db, waiting for 30 seconds and trying again`);
			return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
		}
		console.log(`shared address ${shared_address} found in db, deriving shared address definition to verify it matches the received one`);
		deriveSharedAddress(hash, false, function (err, arrDefinition, assocSignersByPath) {
			if (err) {
				if (retry_count >= 10)
					return console.log(`failed derivation of shared address ${shared_address} after 10 retries, giving up`, err);
				console.log("error deriving shared address definition, will retry in 30 seconds", err);
				return setTimeout(handleReceivedSharedAddress, 30000, hash, shared_address, from_cosigner, retry_count + 1);
			}
			const expected_shared_address = objectHash.getChash160(arrDefinition);
			if (expected_shared_address !== shared_address)
				return console.log(`expected shared address ${expected_shared_address} does not match received from offeror ${shared_address}`, JSON.stringify(arrDefinition, null, 2));
			console.log(`shared address ${expected_shared_address} matches the received one, setting it to the contract and sharing with cosigners`);
			setField(hash, "shared_address", shared_address, function (contract) {
				eventBus.emit("arbiter_contract_update", contract, "shared_address", shared_address);
			}, from_cosigner);
		});
	});
}
```

**File:** arbiter_contract.js (L660-690)
```javascript
function handleReceivedSigningUnit(contract, unit, from_cosigner, retry_count = 0) {
	db.query("SELECT 1 FROM unit_authors WHERE unit=? AND address=?", [unit, contract.shared_address], async function (rows) {
		if (rows.length === 0) {
			if (retry_count >= 10)
				return console.log(`signing tx ${unit} not found in db after 10 retries, giving up`);
			console.log(`signing tx ${unit} not yet in db, waiting for 30 seconds and trying again`);
			return setTimeout(handleReceivedSigningUnit, 30000, contract, unit, from_cosigner, retry_count + 1);
		}
		console.log(`signing tx ${unit} found in db, setting contract's unit and status to signed`);
		const objUnit = await storage.readUnit(unit);
		const dataMessage = objUnit.messages.find(message => message.app === "data");
		if (!dataMessage)
			return console.log(`data message not found in purported signing unit ${unit}`);
		const { payload } = dataMessage;
		const contacts_hash = getContactsHash(contract);
		if (payload.arbiter !== contract.arbiter_address || payload.contract_text_hash !== contract.hash || payload.contacts_hash !== contacts_hash)
			return console.log(`data message payload does not match contract ${contract.hash} in purported signing unit ${unit}`);
		const author = objUnit.authors.find(author => author.address === contract.shared_address);
		const signing_paths = Object.keys(author.authentifiers);
		const isMutuallySigned = signing_paths.find(p => p.startsWith('r.0.0')) && signing_paths.find(p => p.startsWith('r.0.1'));
		if (!isMutuallySigned)
			return console.log(`signing unit ${unit} is not mutually signed, authentifiers: ${JSON.stringify(author.authentifiers)}`);
		const err = await fillArbstoreAddresses(contract);
		if (err)
			console.log(`failed to fill arbstore addresses for contract ${contract.hash} while handling received signing unit ${unit}`, err);
		setField(contract.hash, "status", "signed", null, true);
		setField(contract.hash, "unit", unit, function(contract) {
			eventBus.emit("arbiter_contract_update", contract, "unit", unit);
		}, from_cosigner);
	});
}
```

**File:** arbiter_contract.js (L826-844)
```javascript
// contract payment received
eventBus.on("new_my_transactions", function newtxs(arrNewUnits) {
	db.query("SELECT hash, outputs.unit FROM wallet_arbiter_contracts\n\
		JOIN outputs ON outputs.address=wallet_arbiter_contracts.shared_address\n\
		CROSS JOIN units ON units.unit=outputs.unit\n\
		WHERE outputs.unit IN (" + arrNewUnits.map(db.escape).join(', ') + ") AND outputs.asset IS wallet_arbiter_contracts.asset AND (wallet_arbiter_contracts.status='signed' OR wallet_arbiter_contracts.status='accepted') AND units.sequence='good'\n\
		GROUP BY outputs.address\n\
		HAVING SUM(outputs.amount) >= wallet_arbiter_contracts.amount", function(rows) {
			rows.forEach(function(row) {
				getByHash(row.hash, function(contract){
					if (contract.status === 'accepted') { // we received payment already but did not yet receive signature unit message, wait for unit to be received
						eventBus.on('arbiter_contract_update', function retryPaymentCheck(objContract, field, value){
							if (objContract.hash === contract.hash && field === 'unit') {
								newtxs(arrNewUnits);
								eventBus.removeListener('arbiter_contract_update', retryPaymentCheck);
							}
						});
						return;
					}
```

**File:** network.js (L1035-1045)
```javascript
function purgeExpiredUnitsWaitingForPrunedContent(){
	const now = Date.now();
	for (let missing_unit in assocUnitsWaitingForPrunedContent){
		const arrExpired = assocUnitsWaitingForPrunedContent[missing_unit].filter(o => o.expiry_ts < now);
		arrExpired.forEach(o => kvstore.del('wj\n' + o.unit));
		assocUnitsWaitingForPrunedContent[missing_unit] = assocUnitsWaitingForPrunedContent[missing_unit].filter(o => o.expiry_ts >= now);
		if (assocUnitsWaitingForPrunedContent[missing_unit].length === 0)
			delete assocUnitsWaitingForPrunedContent[missing_unit];
	}
}
setInterval(purgeExpiredUnitsWaitingForPrunedContent, 60 * 60 * 1000);
```

**File:** wallet.js (L948-953)
```javascript
var handledChainsCache = {};
setInterval(() => {
	for (let cache_key in handledChainsCache)
		if (handledChainsCache[cache_key] < Date.now() - 3600 * 1000)
			delete handledChainsCache[cache_key];
}, 3600 * 1000); // clear cache every hour
```
