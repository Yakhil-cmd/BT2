### Title
Stale off-chain `signed_message`/`is_valid_signed_package` authorizations remain valid after the signer's address definition (keys) changes - ([File: signed_message.js])

### Summary
The Farcaster `IdRegistry` bug is a stale-authorization problem: a pre-signed EIP-712 message granting a future permission is not invalidated when the underlying state (recovery address) is changed by a different path, so the stale signature can still be executed later. Ocore has a structurally identical off-chain authorization primitive — `signed_message.validateSignedMessage()` combined with the oscript function `is_valid_signed_package()` — which pins the signature's validity to the address definition that existed *at the time the message was signed* (`last_ball_unit`/`last_ball_mci` embedded in the package) rather than the definition active *when the package is later verified/used* by an AA.

### Finding Description
`validateSignedMessage()` in `signed_message.js` resolves the signer's authorization purely from the historical state referenced inside the package itself: [1](#0-0) 
When `bNetworkAware` is true, it looks up `main_chain_index` for the `last_ball_unit` supplied by the signer and then calls `storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, ...)` — i.e., it fetches the address's definition **as of that historical mci**, not the definition that is current at verification time.

This primitive is exposed to AA (oscript) logic via `is_valid_signed_package`: [2](#0-1) 
The only freshness/replay check performed is that the referenced `last_ball_unit` must be stable and not later than the current evaluation mci (`last_ball_mci > mci` → reject). There is **no check that the signer's address definition is still the same as (or consistent with) the definition currently active for that address**. So if Alice signs a package while her address definition is D1, and later changes her address definition to D2 (e.g., to revoke a cosigner, rotate a compromised key, or otherwise change control), the old package — verified against the D1 snapshot recorded at `last_ball_mci` — remains permanently re-usable by anyone who holds it.

This is exactly the class of bug described in the report: a change to an address's authorization state (definition change) does not retroactively invalidate a previously produced, not-yet-consumed authorization artifact (the signed package), because the verification path checks the *old* state snapshot instead of binding validity to the *current* state.

The official sample AA `test/samples/payment_channels.oscript` demonstrates the intended usage pattern for `is_valid_signed_package`, and shows that AA authors are expected to add their own extra state-binding (e.g., `signed_message.period != var['period']`) to prevent replay/staleness: [3](#0-2) 
Any AA author who uses `is_valid_signed_package` for a "commit now, redeem/authorize later" style permission (analogous to `changeRecoveryAddressFor`) without independently re-binding it to the AA's *current* on-chain state (a fresh nonce, counter, or the current definition/permission set) inherits the exact staleness bug: the core primitive gives no protection by itself.

### Impact Explanation
Any AA that accepts an `is_valid_signed_package(package, address)` result as sufficient proof of a still-valid, still-intended authorization (rather than merely "address once produced this exact byte string") is exposed to replay of a revoked/stale authorization. If such an AA moves funds, changes AA-internal permission state, or grants withdrawal rights based on this check, a counterparty holding an old signed package can submit it after the signer has changed their address definition specifically to revoke that authorization — leading to unauthorized fund transfer or AA state corruption (fund loss). This matches the required "concrete AA fund loss" bar, though the loss is realized only in AAs that use the primitive as a sole authorization gate without additional state binding.

### Likelihood Explanation
Medium. The vulnerable pattern requires an AA design that (a) uses `is_valid_signed_package` for delegated/future-executable authorization and (b) omits its own nonce/counter/state binding. The official sample code (`payment_channels.oscript`) shows the *correct* pattern (binding to `var['period']`), implying the underlying primitive alone is not sufficient and that developers must be aware of this — i.e., the root cause (verification pinned to historical definition snapshot, no current-definition/replay check) is a genuine gap in the core primitive that a less careful AA author could easily fall into, mirroring exactly how the Farcaster team needed to add the current recovery address into the signature to close the gap.

### Recommendation
Add an explicit, opt-in freshness guarantee to `is_valid_signed_package`/`validateSignedMessage`, e.g.:
- Optionally require (or expose to oscript) verification that the address definition referenced/implied by the package still equals the address's *current* definition chash at the AA's execution mci, so key rotation/definition changes automatically invalidate previously issued packages, or
- Document prominently (and provide a helper oscript primitive) that any AA using `is_valid_signed_package` for future-redeemable authorizations must independently bind the signed content to a monotonically increasing AA-state counter/nonce (as `payment_channels.oscript` already does), and add this binding by default rather than leaving it to each AA author.

### Proof of Concept
1. Alice's address `A` has definition D1 (e.g., `["sig", {pubkey: P1}]`).
2. Alice signs a `signed_message` package (via `signed_message.signMessage`) authorizing "grant AA the right to transfer 100 bytes to Bob", with `last_ball_unit` pointing to a stable unit where her definition is D1. She sends this package to Bob off-chain but has not yet had it consumed by the AA.
3. Alice decides not to proceed and posts an `address_definition_change` unit changing her address `A`'s definition to D2 (e.g., revoking the key or changing to a multisig requiring Carol's cosignature), intending this to also revoke any pending authorization tied to her old key.
4. Bob nonetheless submits a trigger to the AA containing the untouched, old signed package.
5. The AA calls `is_valid_signed_package(package, 'A')`; `validateSignedMessage` resolves the definition from the package's embedded `last_ball_unit` (still D1, pre-revocation) and the signature checks out — `is_valid_signed_package` returns `true` even though `A`'s *current* definition is now D2 and Alice never authorized anything under D2.
6. If the AA's business logic (unlike the reference `payment_channels.oscript`, which separately checks `var['period']`) treats a `true` result as sufficient current authorization, it executes the transfer, which is the "recovery-address-analog" outcome the external report warns about: a stale pre-authorization surviving an unrelated, intended-to-be-invalidating state change.

### Citations

**File:** signed_message.js (L197-238)
```javascript
	function validateOrReadDefinition(objAuthor, cb, bRetrying) {
		var bHasDefinition = ("definition" in objAuthor);
		if (bNetworkAware) {
			conn.query("SELECT main_chain_index, timestamp FROM units WHERE unit=?", [objSignedMessage.last_ball_unit], function (rows) {
				if (rows.length === 0) {
					var network = require('./network.js');
					if (!conf.bLight && !network.isCatchingUp() || bRetrying)
						return handleResult("last_ball_unit " + objSignedMessage.last_ball_unit + " not found");
					if (conf.bLight)
						network.requestHistoryFor([objSignedMessage.last_ball_unit], [objAuthor.address], function () {
							validateOrReadDefinition(objAuthor, cb, true);
						});
					else
						eventBus.once('catching_up_done', function () {
							// no retry flag, will retry multiple times until the catchup is over
							validateOrReadDefinition(objAuthor, cb);
						});
					return;
				}
				bRetrying = false;
				var last_ball_mci = rows[0].main_chain_index;
				var last_ball_timestamp = rows[0].timestamp;
				storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, {
					ifDefinitionNotFound: function (definition_chash) { // first use of the definition_chash (in particular, of the address, when definition_chash=address)
						if (!bHasDefinition) {
							if (!conf.bLight || bRetrying)
								return handleResult("definition expected but not provided");
							var network = require('./network.js');
							return network.requestHistoryFor([], [objAuthor.address], function () {
								validateOrReadDefinition(objAuthor, cb, true);
							});
						}
						if (objectHash.getChash160(objAuthor.definition) !== definition_chash)
							return handleResult("wrong definition: "+objectHash.getChash160(objAuthor.definition) +"!=="+ definition_chash);
						cb(objAuthor.definition, last_ball_mci, last_ball_timestamp);
					},
					ifFound: function (arrAddressDefinition) {
						if (bHasDefinition)
							return handleResult("should not include definition");
						cb(arrAddressDefinition, last_ball_mci, last_ball_timestamp);
					}
				});
```

**File:** formula/evaluation.js (L1684-1699)
```javascript
						if (typeof signedPackage.last_ball_unit === 'string') {
							const [row] = await conn.query("SELECT main_chain_index, is_on_main_chain FROM units WHERE unit=?", [signedPackage.last_ball_unit]);
							if (!row || row.main_chain_index > mci || row.main_chain_index === null) // not existing or not stable last ball unit
								return cb(false);
							if (!row.is_on_main_chain && mci >= constants.pemCurvesFixMci) // last ball must be on the MC
								return cb(false);
							if (mci >= constants.pemCurvesFixMci && row.main_chain_index < constants.pemCurvesFixMci) // last ball unit is before the fix
								return setFatalError("last ball unit is before the PEM curves fix", { arr }, false, cb);
						}
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
```

**File:** test/samples/payment_channels.oscript (L40-49)
```text
							if (trigger.data.sentByPeer){
								if (trigger.data.sentByPeer.signed_message.channel != this_address)
									bounce('signed for another channel');
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
								$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
								if ($transferredFromPeer < 0)
									bounce('bad amount spent by peer: ' || $transferredFromPeer);
```
