### Title
Rerouted network requests leave a stale `assocPendingRequests[tag]` entry, causing duplicate handling of a late peer response - ([File: network.js])

### Summary
`network.js`'s `sendRequest()` implements a stalled-request reroute mechanism for reroutable requests (e.g. `get_joint`, catchup/hash-tree fetches). When `STALLED_TIMEOUT` elapses, `reroute()` fires, marks the pending-request entry with `bRerouted = true`, and re-sends the same `responseHandlers` array to a next peer — but it never deletes `ws.assocPendingRequests[tag]` on the original peer. This mirrors the CVE-2025-68746 root cause: on a timeout, the code fails to clear the stale reference (`curr_xfer`/pending-request record) that a later, still-pending completion path (`IRQ` thread / `handleResponse`) can still act on, since only the fix (clearing `curr_xfer`, or here, deleting the stale request) prevents a subsequent event from reusing dead state.

### Finding Description
In `sendRequest()`, a reroutable request stores its state in `ws.assocPendingRequests[tag]` including a `reroute_timer` set for `STALLED_TIMEOUT`: [1](#0-0) 

When the timer fires, `reroute()` checks that the entry still exists, sets `bRerouted = true`, and re-dispatches the same `responseHandlers` to a new peer connection via a fresh `sendRequest(next_ws, ...)` call — but the original `ws.assocPendingRequests[tag]` entry is left in place (not deleted): [2](#0-1) 

Meanwhile, `handleResponse(ws, tag, response)` unconditionally looks up `ws.assocPendingRequests[tag]` and, if found, invokes **all** `responseHandlers` for that tag and then deletes the entry: [3](#0-2) 

Because the original entry on `ws` was never cleared when the reroute fired, if the original (slow/unresponsive) peer eventually does send a late response for the same `tag`, `handleResponse` will invoke the same `responseHandlers` array a second time — even though those handlers were already invoked once via the rerouted peer's response. This is functionally the same bug class as the kernel CVE: a timeout-triggered fallback path fails to null out/clear the reference to in-flight state, so a stale completion event is processed against handlers that already ran (or already believe the request is done), rather than being ignored.

### Impact Explanation
Response handlers for reroutable commands (e.g. `get_joint`, hash-tree/catchup content fetches driven by `requestJoints`/`requestCatchup`/`readHashTree` flows) are not designed to be invoked twice for the same tag. A duplicate invocation can cause a joint to be processed/queued twice concurrently (re-entering `handleJoint`/`assocUnitsInWork` bookkeeping from two different code paths simultaneously, since the second call now originates from a different, un-deduplicated invocation context), duplicate catchup-chain processing, or duplicated calls into logic that assumes single-fire semantics. Depending on the exact handler reached twice, this can cause node-level disagreement about processed state/inconsistent internal caches, which the analog rules treat as a "node disagreement on validity or stability"-class impact — reachable purely from a slow/unresponsive-but-eventually-responding remote peer without any malicious behavior required, since the honest peer is simply slow.

### Likelihood Explanation
Triggering requires only a peer whose response is delayed past `STALLED_TIMEOUT` but who still eventually answers after the reroute already got an answer from another peer — a plausible and even likely condition under normal network jitter, not requiring an adversarial peer. No special crafting of message content is needed, only timing.

### Recommendation
On reroute, immediately delete or otherwise invalidate the original `ws.assocPendingRequests[tag]` entry (or track a "handled" flag checked by `handleResponse`) so that a late-arriving response after reroute cannot re-invoke `responseHandlers`. Symmetrically to the kernel fix's approach of nulling `curr_xfer` before the retry/cleanup path runs, `deletePendingRequest(ws, tag)` (or equivalent) should be called as part of `reroute()` before dispatching to the next peer, and `handleResponse` should treat an already-`bRerouted` entry on the original peer as a no-op.

### Proof of Concept
1. Node A sends a reroutable request (e.g. `get_joint`) to peer P1 via `sendRequest(ws1, 'get_joint', unit, true, handler)`.
2. P1 does not respond within `STALLED_TIMEOUT`; `reroute()` fires, sets `ws1.assocPendingRequests[tag].bRerouted = true`, and sends the same `handler` to peer P2 (`sendRequest(ws2, ...)`).
3. P2 responds normally; `handleResponse(ws2, tag, response)` invokes `handler` and deletes `ws2.assocPendingRequests[tag]`.
4. P1, still connected, later sends a delayed response for the original request/tag.
5. `handleResponse(ws1, tag, response)` finds `ws1.assocPendingRequests[tag]` still present (never cleared in step 2) and invokes `handler` a second time with P1's (possibly stale/conflicting) response — duplicate processing of the same logical request.

Note: I was not able to fully trace every downstream `responseHandler` implementation reachable via reroutable requests to confirm the maximum concrete impact (e.g., whether any specific handler leads directly to double-spend or fund loss vs. only inconsistent internal state/log noise); a deeper audit of all `sendRequest(..., true, ...)` call sites and their handlers would be needed to fully bound severity.

### Citations

**File:** network.js (L253-297)
```javascript
		// after STALLED_TIMEOUT, reroute the request to another peer
		// it'll work correctly even if the current peer is already disconnected when the timeout fires
		var reroute = !bReroutable ? null : function(){
			console.log('will try to reroute a '+command+' request stalled at '+ws.peer);
			if (!ws.assocPendingRequests[tag])
				return console.log('will not reroute - the request was already handled by another peer');
			ws.assocPendingRequests[tag].bRerouted = true;
			findNextPeer(ws, function(next_ws){ // the callback may be called much later if findNextPeer has to wait for connection
				if (!ws.assocPendingRequests[tag])
					return console.log('will not reroute after findNextPeer - the request was already handled by another peer');
				if (next_ws === ws || assocReroutedConnectionsByTag[tag] && assocReroutedConnectionsByTag[tag].indexOf(next_ws) >= 0){
					console.log('will not reroute '+command+' to the same peer, will rather wait for a new connection');
					eventBus.once('connected_to_source', function(){ // try again
						console.log('got new connection, retrying reroute '+command);
						reroute();
					});
					return;
				}
				console.log('rerouting '+command+' from '+ws.peer+' to '+next_ws.peer);
				ws.assocPendingRequests[tag].responseHandlers.forEach(function(rh){
					sendRequest(next_ws, command, params, bReroutable, rh);
				});
				if (!assocReroutedConnectionsByTag[tag])
					assocReroutedConnectionsByTag[tag] = [ws];
				assocReroutedConnectionsByTag[tag].push(next_ws);
			});
		};
		var reroute_timer = !bReroutable ? null : setTimeout(reroute, STALLED_TIMEOUT);
		var cancel_timer = bReroutable ? null : setTimeout(function(){
			ws.assocPendingRequests[tag].responseHandlers.forEach(function(rh){
				rh(ws, request, {error: "[internal] response timeout"});
			});
			delete ws.assocPendingRequests[tag];
		}, RESPONSE_TIMEOUT);
		ws.assocPendingRequests[tag] = {
			request: request,
			responseHandlers: [responseHandler], 
			reroute: reroute,
			reroute_timer: reroute_timer,
			cancel_timer: cancel_timer
		};
		sendMessage(ws, 'request', content);
	}
	return tag;
}
```

**File:** network.js (L325-339)
```javascript
function handleResponse(ws, tag, response){
	if (!ValidationUtils.isNonemptyString(tag))
		return console.log("no tag in response");
	var pendingRequest = ValidationUtils.hasOwnProperty(ws.assocPendingRequests, tag) && ws.assocPendingRequests[tag];
	if (!pendingRequest) // was canceled due to timeout or rerouted and answered by another peer
		//throw "no req by tag "+tag;
		return console.log("no req by tag "+tag);
	pendingRequest.responseHandlers.forEach(function(responseHandler){
		process.nextTick(function(){
			responseHandler(ws, pendingRequest.request, response);
		});
	});

	deletePendingRequest(ws, tag);
}
```
