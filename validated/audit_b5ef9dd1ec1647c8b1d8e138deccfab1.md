### Title
Unbounded growth of `handledChainsCache` allows memory-exhaustion DoS via crafted private-payment chains - (File: wallet.js)

### Summary
`wallet.js` maintains an in-memory de-duplication cache `handledChainsCache` for incoming private-payment chain messages. Every distinct `arrChains` payload received from a paired device / hub correspondent adds a new entry keyed by a hash of the whole payload, and entries are only swept once per hour by age, with no cap on the number of entries or on the rate/volume of insertion. This is directly analogous to CVE-2021-3637 (GHSA-2vp8-jv5v-6qh6), where Keycloak's `authenticationSessions` map grew without limit because sessions were added on every request and cleaned only lazily, enabling attacker-driven memory exhaustion.

### Finding Description
`handledChainsCache` is declared as a plain object with only a periodic, age-based cleanup: [1](#0-0) 

`handlePrivatePaymentChains` computes a cache key from the entire attacker-supplied `arrChains` array (`objectHash.getBase64Hash(arrChains)`) after only cheap structural validation (non-empty arrays/objects, presence of `unit`, `payload.asset`, `inputs`, `outputs` — no signature, unit-existence, or asset-existence checks at this stage): [2](#0-1) 

If the same `cache_key` was seen before, the handler short-circuits; otherwise it proceeds to `network.handleOnlinePrivatePayment` for each chain and, on success, unconditionally stores the entry: [3](#0-2) 

Crucially, "success" here does not require the referenced unit to actually exist or be valid. In `network.handleOnlinePrivatePayment`, when the head unit is unknown (the common case for an attacker-fabricated chain with a fresh, well-formed but non-existent 44-byte base64 `unit` value) the code simply persists the payload for later processing and calls `ifQueued()`, which is treated as success by the wallet-side loop: [4](#0-3) 

Because each `ifQueued` outcome results in `cb()` with no error in `handlePrivatePaymentChains`'s `async.eachSeries`, an attacker who is a paired device / correspondent (or anyone able to relay messages via a hub to a paired wallet) can send an unbounded stream of distinct, cheaply-constructed fake private-payment chains (random `unit` values, arbitrary `payload.asset`/`inputs`/`outputs`) to keep generating unique cache keys. Each one:
1. Adds a permanent (until the next hourly sweep, and only if older than 1 hour) entry to `handledChainsCache` in the wallet process's memory, and
2. Also inserts a row into `unhandled_private_payments` via `savePrivatePayment`, compounding the resource cost.

There is no maximum size enforced on `handledChainsCache`, no per-sender rate limit, and no cost (fee, PoW, or bandwidth throttling) tied to sending these messages, matching the CWE-770 "Allocation of Resources Without Limits or Throttling" pattern from the advisory.

### Impact Explanation
An attacker who is a paired device or a correspondent able to send `private_payments` messages (forwarded through a hub) to a victim wallet/node can force unbounded growth of `handledChainsCache` and the backing `unhandled_private_payments` table faster than the hourly cleanup can reclaim memory. This can exhaust the victim node's memory, crashing the process. If the affected node also participates in relaying/witnessing/serving DAG data, this results in the node becoming unable to process or confirm new units, which the assessment criteria treat as a qualifying impact ("a network unable to confirm new units") for a resource-exhaustion class of bug.

### Likelihood Explanation
The attack requires no privileged access — only the ability to be a device correspondent/pairing counterpart or to have a hub relay `private_payment_chains` messages to the target, which is a normal wallet-to-wallet communication path. Constructing the payloads only requires passing cheap structural checks (`isNonemptyArray`/`isNonemptyObject` and valid-looking hash-length strings) — no valid signatures, real units, or actual assets are needed to reach the point where the cache entry is created. This makes the attack inexpensive to mount at high volume.

### Recommendation
- Bound `handledChainsCache` by size (e.g., LRU/max-size eviction similar to `MAX_ITEMS_IN_CACHE` used elsewhere in `storage.js`) in addition to the age-based sweep.
- Rate-limit or cap the number of distinct/unresolved private-payment chains accepted per sender/device within a time window before they are proven to reference a genuine unit.
- Consider requiring proof that the referenced `unit` corresponds to a real, retrievable unit (or at least bounding the number of "waiting" chains per unit/sender) before allocating a cache entry, mirroring the safeguards already used for other in-memory caches such as `assocUnitsWaitingForPrunedContent` in `network.js`, which explicitly documents anti-memory-exhaustion intent.

### Proof of Concept
1. As a paired device (or a correspondent relayed through the hub), repeatedly send `private_payment_chains` messages to the victim, each with a freshly randomized but well-formed 44-character base64 `unit` string, and syntactically valid but otherwise fabricated `payload` (`asset`, `inputs`, `outputs` non-empty objects).
2. Each message computes a unique `cache_key = objectHash.getBase64Hash(arrChains)` and passes the structural checks in `handlePrivatePaymentChains` (wallet.js:959-972).
3. `network.handleOnlinePrivatePayment` reaches the `ifNew`/light "queued" branch because the fabricated `unit` is unknown, calling `callbacks.ifQueued()` (network.js:2430-2436), which the wallet-side loop treats as success.
4. `handledChainsCache[cache_key] = Date.now()` is set unconditionally on this "success" path (wallet.js:1072), and a row is persisted to `unhandled_private_payments`.
5. Repeating this at high volume for under an hour accumulates entries in `handledChainsCache` and rows in `unhandled_private_payments` without bound, since the sweep interval (wallet.js:949-953) only removes entries older than 1 hour and there is no size cap — leading to unbounded memory/DB growth and potential DoS of the victim node.

**Caveat:** I was not able to execute this against a running node in this environment; the analysis is based on static code review of the reachable path described above. I am reasonably confident in the code paths cited, but the exact memory-growth rate and whether other layers (e.g., hub-side flood limits not visible in this repo) mitigate it in practice would need runtime verification.

### Citations

**File:** wallet.js (L948-953)
```javascript
var handledChainsCache = {};
setInterval(() => {
	for (let cache_key in handledChainsCache)
		if (handledChainsCache[cache_key] < Date.now() - 3600 * 1000)
			delete handledChainsCache[cache_key];
}, 3600 * 1000); // clear cache every hour
```

**File:** wallet.js (L955-978)
```javascript
function handlePrivatePaymentChains(ws, body, from_address, callbacks){
	var arrChains = body.chains;
	if (!ValidationUtils.isNonemptyArray(arrChains))
		return callbacks.ifError("no chains found");
	if (!arrChains.every(c =>
		isNonemptyArray(c) &&
		c.every(e =>
			isNonemptyObject(e) &&
			isNonemptyString(e.unit) &&
			isNonemptyObject(e.payload) &&
			isNonemptyString(e.payload.asset) &&
			isNonemptyArray(e.payload.inputs) &&
			isNonemptyArray(e.payload.outputs) &&
			e.payload.inputs.every(isNonemptyObject) &&
			e.payload.outputs.every(isNonemptyObject)
		)
	))
		return callbacks.ifError("malformed private chain");
	try {
		var cache_key = objectHash.getBase64Hash(arrChains);
	}
	catch (e) {
		return callbacks.ifError("chains hash failed: " + e.toString());		
	}
```

**File:** wallet.js (L1065-1073)
```javascript
		function(err){
			bParsingComplete = true;
			if (err){
				cancelAllKeys();
				return callbacks.ifError(err);
			}
			checkIfAllValidated();
			handledChainsCache[cache_key] = Date.now();
			callbacks.ifOk();
```

**File:** network.js (L2412-2440)
```javascript
	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
		},
		ifNew: function(){
			savePrivatePayment();
			// if received via hub, I'm requesting from the same hub, thus telling the hub that this unit contains a private payment for me.
			// It would be better to request missing joints from somebody else
			requestNewMissingJoints(ws, [unit]);
		},
		ifKnownUnverified: savePrivatePayment,
		ifKnownBad: function(){
			callbacks.ifValidationError(unit, "known bad");
		}
	});
```
