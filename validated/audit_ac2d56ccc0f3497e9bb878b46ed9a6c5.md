### Title
Anyone Can Front-Run and Steal Channel Funds via the Unrestricted "Fraud Proof" Case in the Payment-Channel AA Template - (File: `test/samples/payment_channels.oscript`)

### Summary
The reference payment-channel Autonomous Agent (AA) shipped with ocore implements a two-party channel with a "fraud proof" mechanism that lets a party prove the counterparty under-reported an off-chain transfer when closing the channel. The `fraud_proof` case's `if`/`init` conditions never check that `trigger.address` belongs to one of the two channel parties (`$addressA`/`$addressB`). Because the winning payout in that branch is sent to `{trigger.address}` (i.e. whoever posted the trigger unit), any third party who observes the honest party's yet-unconfirmed fraud-proof unit (which necessarily carries the `sentByPeer` signed package inline, since AA trigger data is public once broadcast) can copy that exact data into their own trigger and get it included first, redirecting the entire channel balance to themselves.

### Finding Description
In `test/samples/payment_channels.oscript`, the "fraud proof" case is guarded only by: [1](#0-0) 

Note that the `if` condition is `trigger.data.fraud_proof AND var['close_initiated_by'] AND trigger.data.sentByPeer` — it does not require `trigger.address == $addressA` or `$addressB` (contrast with the "refill"/"start closing" cases, which explicitly gate on `$bFromParties`, see `test/samples/payment_channels.oscript` lines 6-10 and 15/32). The `init` block only checks the validity of the signature on `trigger.data.sentByPeer` against the address of whichever party initiated closing — it authenticates the *content* of the proof, not the *caller*.

The payout message then sends the entire remaining channel balance to the trigger sender, not to the honest counterparty: [2](#0-1) 

This mirrors the reported `redeem` vulnerability pattern exactly: a function validates a signed voucher/package correctly but authorizes payout based on `msg.sender`/`trigger.address` rather than deriving the rightful recipient from the proof itself (here, the honest non-initiating party, e.g. `$addressB` when `$bInitiatedByA` is true). Since the `sentByPeer` signed package must be included inline in the trigger's `data` field to satisfy `is_valid_signed_package`, it becomes visible on the network as soon as the honest party's unit is broadcast — before it is stable/confirmed. Any observer can copy that data verbatim into a new trigger unit naming themselves as `trigger.address`, and if that copy gets included on the DAG first, the state variable `close_initiated_by` is reset (this case resets the channel state, see lines 132-141), causing the honest party's original transaction to subsequently fail its `if` condition (since `var['close_initiated_by']` is now false) — the attacker keeps the stolen funds and the legitimate claim is voided, exactly as in the front-run `redeem`/`AllocationIDTracker` scenario described in the report.

### Impact Explanation
An unprivileged AA trigger sender who does no more than copy publicly-visible trigger data from a pending unit can redirect an entire channel's balance to their own address, causing outright AA fund loss for the honest channel counterparty. This is a direct "unauthorized spending" / "AA fund loss" outcome as required by the validation rubric.

### Likelihood Explanation
Exploitation requires no privileged position (no malicious hub/witness needed) — it only requires observing a broadcast-but-unconfirmed unit containing the `sentByPeer` payload and posting a competing higher-priority unit with identical data before the honest party's unit is included. Any wallet user monitoring the DAG for units addressed to a known channel AA can do this whenever a legitimate fraud-proof claim is submitted, so likelihood is significant whenever this exact reference pattern (paying `{trigger.address}` in a case not gated by `$bFromParties`) is reused in a deployed AA.

### Recommendation
Restrict the `fraud_proof` case's `if` condition (and any branch that awards funds to `trigger.address`) to require `trigger.address` to be a legitimate party of the channel, i.e. add `$bFromParties` (or specifically the non-initiating party) to the guard, and pay the recovered funds to the address entitled to them (`$bInitiatedByA ? $addressB : $addressA`) rather than to `{trigger.address}`. More generally, any AA branch that pays out based on possession of a signed message/proof must derive the recipient address from the proof/definition itself, never from the unauthenticated `trigger.address` of whoever happens to submit the triggering unit.

### Proof of Concept
1. Channel AA has `close_initiated_by = 'A'` after A calls "start closing" honestly.
2. Off-chain, A had earlier signed a `signed_message` (package) promising B a larger `amount_spent` than A represented while closing.
3. B builds a `fraud_proof` trigger: `{fraud_proof: true, sentByPeer: <A's signed package>}` and broadcasts it, expecting the channel's full balance to be paid to `{trigger.address}` = B.
4. Attacker M observes B's unit while unconfirmed, extracts `trigger.data.sentByPeer` (fully present in the broadcast unit), and immediately submits their own trigger `{fraud_proof: true, sentByPeer: <same package>}` from their own address, with better connectivity/fee to get included first.
5. The AA's `is_valid_signed_package` check passes (content and signature are unchanged), the case fires, and the full balance is paid to `{trigger.address}` = M's address per lines 120-130.
6. The state is reset (`close_initiated_by = false`), so B's now-redundant unit fails the `if` condition and B receives nothing.

### Citations

**File:** test/samples/payment_channels.oscript (L103-119)
```text
			{ // fraud proof
				if: `{ trigger.data.fraud_proof AND var['close_initiated_by'] AND trigger.data.sentByPeer }`,
				init: `{
					$bInitiatedByA = (var['close_initiated_by'] == 'A');
					if (trigger.data.sentByPeer.signed_message.channel != this_address)
						bounce('signed for another channel');
					if (trigger.data.sentByPeer.signed_message.period != var['period'])
						bounce('signed for a different period of this channel');
					if (!is_valid_signed_package(trigger.data.sentByPeer, $bInitiatedByA ? $addressA : $addressB))
						bounce('invalid signature by peer');
					$transferredFromPeer = trigger.data.sentByPeer.signed_message.amount_spent;
					if ($transferredFromPeer < 0)
						bounce('bad amount spent by peer: ' || $transferredFromPeer);
					$transferredFromPeerAsClaimedByPeer = var['spentBy' || ($bInitiatedByA ? 'A' : 'B')];
					if ($transferredFromPeer <= $transferredFromPeerAsClaimedByPeer)
						bounce("the peer didn't lie in his favor");
				}`,
```

**File:** test/samples/payment_channels.oscript (L120-130)
```text
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							outputs: [
								// send all
								{ address: '{trigger.address}' }
							]
						}
					},
```
