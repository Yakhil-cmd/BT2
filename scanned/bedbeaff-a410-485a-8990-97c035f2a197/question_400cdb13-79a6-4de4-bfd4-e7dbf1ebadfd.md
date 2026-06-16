[File: 'zk_ee/src/common_structs/history_map/mod.rs'] [Function: ElementWithHistory::rollback — committed pointer validity] Can an unprivileged attacker trigger a sequence: (1) begin_new_tx → commit (committed=initial), (2) update key K to V2 (head=V2, committed=initial), (3) commit (committed=V2, intermediate records freed to pool), (4) update key K to V3 (head=V3), (5) rollback to post-step-3 snapshot — where after rollback, head=V2 and committed=V2 (both pointing

```python
questions = [
