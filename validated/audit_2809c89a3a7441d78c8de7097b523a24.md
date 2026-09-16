### Title
Unvalidated peer-supplied `arbiter_address` concatenated into ArbStore API URL path enables path/query injection to unintended endpoints - (File: `arbiters.js`)

### Summary
`arbiters.js` builds ArbStore HTTP request URLs by directly string-concatenating an `arbiter_address` value into the URL path: `url+'/api/arbiter/'+address` and `url+'/api/get_info'` [1](#0-0) [2](#0-1) . This `address` originates from `objContract.arbiter_address`, a field that is fully attacker-controlled: it is received from a paired peer over `arbiter_contract_offer` / `arbiter_contract_shared` device messages and persisted via `store()` with no address-format (`isValidAddress`) or character sanitization anywhere in `arbiter_contract.js` before being written to `wallet_arbiter_contracts` [3](#0-2) . The stored value is later fed straight into `arbiters.getInfo()` / `arbiters.getArbstoreInfo()` from `openDispute()`, `getAppealFee()`, and `appeal()` [4](#0-3) [5](#0-4) , without any re-validation of its format.

### Finding Description
The bug class mirrors the Gravitino report: a user/peer-supplied identifier is embedded unencoded into a URL path used for an outbound HTTP request, with no percent-encoding, no path-segment sanitization, and no strict format check (`ValidationUtils.isValidAddress`) enforced at the point of use.

Flow:
1. A remote paired device sends an `arbiter_contract_offer` (or later `arbiter_contract_shared`) message containing arbitrary JSON, including `arbiter_address`.
2. `store()` inserts this value into `wallet_arbiter_contracts.arbiter_address` verbatim — there is no call to `ValidationUtils.isValidAddress` (or any equivalent) in `arbiter_contract.js` before or during storage [3](#0-2) .
3. When the local wallet later interacts with the contract (`openDispute`, `getAppealFee`, `appeal`), it calls `arbiters.getInfo(objContract.arbiter_address, ...)` [6](#0-5) .
4. Inside `getInfo`, the address is concatenated raw into the request path sent to the ArbStore host resolved via the hub: `requestInfoFromArbStore(url+'/api/arbiter/'+address, ...)` [1](#0-0) .

Because `address` is never checked to be a well-formed 32-character base32 address before this concatenation, an attacker can set `arbiter_address` to a string containing `/../`, `?`, `#`, or additional path segments, causing the constructed URL to target a different path/endpoint on the ArbStore server than the developer intended (e.g., bypassing `/api/arbiter/<addr>` to hit another API route, or appending spoofed query parameters that the ArbStore backend may parse differently than expected).

### Impact Explanation
The ArbStore host itself is resolved from the hub (`hub/get_arbstore_url`), so the attacker cannot fully redirect requests to an arbitrary external host through this bug alone, but the attacker fully controls the *path* segment appended to that host. This can be leveraged to reach unintended ArbStore API endpoints under the same host — for example smuggling a crafted path that resolves to a different arbiter/dispute/appeal action than the one displayed to the victim, potentially manipulating dispute/appeal flow outcomes tied to funds locked in a shared arbiter contract address. This is a path-confusion/path-traversal-to-unintended-endpoint condition of the exact class described in the report, reachable purely by a peer proposing a malicious arbiter contract offer — no privileged access required.

### Likelihood Explanation
High reachability: any paired device (a normal wallet counterparty in an arbiter-mediated deal) can send an `arbiter_contract_offer`/`arbiter_contract_shared` message with an arbitrary string in `arbiter_address`, and the victim wallet will use it verbatim once the victim interacts with the contract (opens a dispute, checks appeal fee, or files an appeal). No signature or address-format check gates this value before use in the HTTP path build.

### Recommendation
- Validate `arbiter_address` with `ValidationUtils.isValidAddress()` immediately upon receipt/storage in `store()` and `createAndSend()` in `arbiter_contract.js`, rejecting the contract offer if invalid.
- In `arbiters.js`, re-validate `address` with `ValidationUtils.isValidAddress()` before using it in `getInfo()`/`getArbstoreInfo()`, and construct request paths using `encodeURIComponent()` / the `url` module's structured path-building APIs rather than raw string concatenation.

### Proof of Concept
1. Device A sends an `arbiter_contract_offer` message to Device B with `arbiter_address` set to a crafted value such as `"VALIDADDR32CHARS.."` replaced by `"../get_appeal_fee?x=1"` (or any string containing `/`, `..`, `?`, `#`).
2. Device B calls `store(objContract, false, cb)`, which persists the unvalidated value with no format check [3](#0-2) .
3. Device B later calls `openDispute(hash, cb)`, which internally calls `arbiters.getInfo(objContract.arbiter_address, ...)` [6](#0-5) .
4. `getInfo` builds `url + '/api/arbiter/' + address`, producing a URL whose path segment is attacker-controlled and can escape the intended `/api/arbiter/<address>` route on the ArbStore host [1](#0-0) .

### Citations

**File:** arbiters.js (L16-22)
```javascript
			device.requestFromHub("hub/get_arbstore_url", address, function(err, url){
				if (err) {
					return cb(err);
				}
				if (!validationUtils.isNonemptyString(url))
					return cb("invalid url received from hub");
				requestInfoFromArbStore(url+'/api/arbiter/'+address, function(err, info){
```

**File:** arbiters.js (L60-66)
```javascript
	device.requestFromHub("hub/get_arbstore_url", arbiter_address, function(err, url){
		if (err) {
			return cb(err);
		}
		if (!validationUtils.isNonemptyString(url))
			return cb("invalid url received from hub");
		requestInfoFromArbStore(url+'/api/get_info', function(err, info){
```

**File:** arbiter_contract.js (L91-116)
```javascript
function store(objContract, bFromCosigner, cb) { // contracts shared by cosigners are trusted to reflect their true status
	const me_is_cosigner = bFromCosigner ? 1 : 0;
	const status = bFromCosigner ? (objContract.status || status_PENDING) : status_PENDING;
	var fields = "(hash, peer_address, peer_device_address, my_address, arbiter_address, me_is_payer, my_party_name, peer_party_name, amount, asset, is_incoming, creation_date, ttl, status, title, text, peer_pairing_code, peer_contact_info, my_pairing_code, my_contact_info, me_is_cosigner";
	var placeholders = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?";
	var values = [objContract.hash, objContract.peer_address, objContract.peer_device_address, objContract.my_address, objContract.arbiter_address, objContract.me_is_payer ? 1 : 0, objContract.my_party_name, objContract.peer_party_name, objContract.amount, objContract.asset, 1, objContract.creation_date, objContract.ttl, status, objContract.title, objContract.text, objContract.peer_pairing_code, objContract.peer_contact_info, objContract.my_pairing_code, objContract.my_contact_info, me_is_cosigner];
	if (bFromCosigner) {
		if (objContract.shared_address) {
			fields += ", shared_address";
			placeholders += ", ?";
			values.push(objContract.shared_address);
		}
		if (objContract.unit) {
			fields += ", unit";
			placeholders += ", ?";
			values.push(objContract.unit);
		}
	}
	fields += ")";
	placeholders += ")";
	db.query("INSERT "+db.getIgnore()+" INTO wallet_arbiter_contracts "+fields+" VALUES "+placeholders, values, function(res) {
		if (cb) {
			cb(res);
		}
	});
}
```

**File:** arbiter_contract.js (L262-279)
```javascript
function openDispute(hash, cb) {
	getByHash(hash, function(objContract){
		if (!["paid", "in_dispute"].includes(objContract.status))
			return cb("contract can't be disputed");
		device.requestFromHub("hub/get_arbstore_url", objContract.arbiter_address, function(err, url){
			if (err)
				return cb(err);
			arbiters.getInfo(objContract.arbiter_address, async function(err, objArbiter) {
				if (err)
					return cb(err);
				err = await fillArbstoreAddresses(objContract);
				if (err)
					return cb(err);
				device.getOrGeneratePermanentPairingInfo(function(pairingInfo){
					var my_pairing_code = pairingInfo.device_pubkey + "@" + pairingInfo.hub + "#" + pairingInfo.pairing_secret;
					var data = {
						contract_hash: hash,
						unit: objContract.unit,
```

**File:** arbiter_contract.js (L357-374)
```javascript
function getAppealFee(hash, cb) {
	getByHash(hash, function(objContract){
		var command = "hub/get_arbstore_url";
		var address = objContract.arbiter_address;
		if (objContract.arbstore_address) {
			command = "hub/get_arbstore_url_by_address";
			address = objContract.arbstore_address;
		}
		device.requestFromHub(command, address, function(err, url){
			if (err)
				return cb("can't get arbstore url:", err);
			httpRequest(url, "/api/get_appeal_fee", "", function(err, resp) {
				if (err)
					return cb(err);
				cb(null, resp);
			});
		});
	});
```
