### Title
Oscript `log()` output is leaked to arbitrary requesters via `light/dry_run_aa`, bypassing the codebase's own "do not send logs over the wire" rule - (File: network.js, aa_composer.js)

### Summary
CVE-2017-16946 is a MISP bug where a sensitive field (`enable_password`) was written verbatim into an audit log that admins could read, letting a privileged-but-unauthorized party recover a secret (a password hash) that should have stayed internal. The analogous root cause in `ocore` is that AA `log()` output — data the codebase itself treats as sensitive and explicitly excludes from network responses in one code path — is not filtered in another reachable code path (`light/dry_run_aa`), so any peer can read it for any AA/trigger combination.

### Finding Description
When an AA response is produced, `addResponse()` in `aa_composer.js` attaches whatever the AA logged via the `log(...)` oscript statement to the in-memory response object: [1](#0-0) 

Elsewhere, the project explicitly recognizes that this `logs` data must never be sent to light clients over the wire, and strips it before forwarding a genuine `aa_response` event: [2](#0-1) 

However, the `light/dry_run_aa` request handler, which lets **any connected peer** simulate a trigger against **any AA address** (not just their own address or a triggering unit they actually posted), forwards the full `arrResponses` array — produced by the same `handleTrigger`/`addResponse` code path used for real triggers — straight back to the requester with no equivalent stripping of `.logs`: [3](#0-2) 

Because `dryRunPrimaryAATrigger` shares the identical `addResponse()` logic (the same function shown above that sets `objAAResponse.logs = objValidationState.logs`), any `log()` statement executed during the simulated evaluation is included in the JSON returned to the caller, contradicting the explicit design decision at `network.js:1905-1908` that log entries are not meant to leave the node over the wire.

### Impact Explanation
Many AA designs use `log()` for internal bookkeping/debugging of values that are never meant to be observable off-chain by third parties — e.g., intermediate values in commit-reveal or hash-lock/atomic-swap style contracts, or values derived from another user's private trigger data/state. Because `light/dry_run_aa` accepts an attacker-supplied `trigger` object and `address` with no requirement that the caller is the trigger's author or a party to the AA, an unprivileged peer can repeatedly probe an AA's logic (varying the simulated trigger's data/amount) and read back internal `log()` output that the codebase's own security model says must stay off the wire. Depending on what the AA logs (e.g., partial reveal of a secret compared inside a hash-lock condition, or an intermediate value gating fund release), this can let an attacker infer secrets needed to claim funds ahead of the legitimate party, causing unauthorized spending/fund loss from the affected AA.

### Likelihood Explanation
`light/dry_run_aa` is a normal, unauthenticated light-wallet RPC command exposed to any connected peer; it requires no special privilege beyond knowing the AA's address and constructing a syntactically valid trigger object (validated only by `aa_composer.validateAATriggerObject`). No unit needs to be broadcast or paid for since it's a simulation, making repeated probing cheap and easy for any attacker.

### Recommendation
Strip `logs` from the responses returned by `light/dry_run_aa` (and any other RPC that surfaces `aa_composer` response objects to remote peers) in the same way it is already stripped before the `aa_response` event is forwarded to light clients at `network.js:1905-1908`, i.e., delete `objAAResponse.logs` for every entry in `arrResponses` before calling `sendResponse` in the `light/dry_run_aa` handler.

### Proof of Concept
1. An AA is deployed that uses `log(...)` internally to record a secret/intermediate value used in a hash-lock or commit-reveal condition gating a payout.
2. An attacker who is not a party to the intended trigger connects to any full node as a light client and sends a `light/dry_run_aa` request (`network.js:3939`) with `address` set to the target AA and a crafted `trigger` object approximating the real one.
3. The node executes `aa_composer.dryRunPrimaryAATrigger`, which internally calls the same `addResponse()` used for real triggers, attaching `objValidationState.logs` (`aa_composer.js:1622-1623`) to the response.
4. `network.js:3951-3959` returns `arrResponses` — including the `logs` field — directly to the attacker via `sendResponse`, whereas the equivalent real-time `aa_response` broadcast path at `network.js:1905-1908` would have stripped it.
5. The attacker inspects the returned `logs` to recover the internal value the AA author intended to keep off the wire, and uses it to front-run or claim funds from the AA.

Note: I was not able to fully trace `dryRunPrimaryAATrigger`'s internal body (only its call sites and the shared `addResponse` helper were retrieved) before the tool budget was exhausted, so the exact conditions under which `logs` is populated in a dry run versus a real trigger are inferred from the shared code path rather than a full independent read of that specific function — this should be verified directly in `aa_composer.js` before treating the PoC as fully confirmed.

### Citations

**File:** aa_composer.js (L1622-1623)
```javascript
		if (objValidationState.logs)
			objAAResponse.logs = objValidationState.logs;
```

**File:** network.js (L1905-1908)
```javascript
		if (objAAResponse.logs) { // do not send the logs over the wire
			objAAResponse = _.clone(objAAResponse);
			delete objAAResponse.logs;
		}
```

**File:** network.js (L3939-3960)
```javascript
		case 'light/dry_run_aa':
			if (!params)
				return sendErrorResponse(ws, tag, "no params in light/dry_run_aa");
			if (!ValidationUtils.isValidAddress(params.address))
				return sendErrorResponse(ws, tag, "address not valid");
		
			storage.readAADefinition(db, params.address, null, function (arrDefinition) {
				if (!arrDefinition)
					return sendErrorResponse(ws, tag, "not an AA");
				aa_composer.validateAATriggerObject(params.trigger, function(error){
					if (error)
						return sendErrorResponse(ws, tag, error);
					aa_composer.dryRunPrimaryAATrigger(params.trigger, params.address, arrDefinition, function (arrResponses) {
						if (constants.COUNT_WITNESSES === 1) { // the temp unit might have rebuilt the MC
							db.executeInTransaction(function (conn, onDone) {
								storage.resetMemory(conn, onDone);
							});
						}
						if (ws.library_version === '0.4.2' && arrResponses.length === 1 && arrResponses[0].bounced && typeof arrResponses[0].response.error === 'object')
							arrResponses[0].response.error = arrResponses[0].response.error.message;
						sendResponse(ws, tag, arrResponses);
					});
```
