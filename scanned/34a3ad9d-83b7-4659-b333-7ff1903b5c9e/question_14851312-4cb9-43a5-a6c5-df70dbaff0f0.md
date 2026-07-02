[File: 'core/src/fetch_stage.rs'] [Function: handle_forwarded_packets] Can an unprivileged QUIC client, by flooding the forward_receiver channel with >1024 packets per batch cycle, cause the poh_recorder.would_be_leader() check to be evaluated only once for the entire accumulated batch, so that a leader-status change occurring between batch accumulation and the try_send calls causes all forwarded vote transactions to be silently dropped for the entire slot, violating the invariant that valid forwarded votes must reach banking stage when the node is leader, causing scoped impact: High. Unintended chain split (network partition) due to vote starvation on the leader? Proof idea: unit

```python
questions = [
