# Q959: heaviest_subtree_fork_choice Leader-progress starvation from adversarial replay work

## Question
Can an attacker shape fork timing, vote ordering, duplicate shreds, ancestry hints, and replay-visible state through vote, shred, or transaction input that influences replay so `core/src/consensus/heaviest_subtree_fork_choice.rs::update_with_newly_valid_ancestor` spends enough replay or vote-processing work on adversarial forks that valid leader progress is delayed past bounty-grade liveness thresholds without brute force?

## Target
- File/function: core/src/consensus/heaviest_subtree_fork_choice.rs::update_with_newly_valid_ancestor
- Entrypoint: vote, shred, or transaction input that influences replay
- Attacker controls: fork timing, vote ordering, duplicate shreds, ancestry hints, and replay-visible state
- Exploit idea: Probe whether bounded adversarial fork fanout or duplicate evidence monopolizes replay-critical workers or ancestor traversal.
- Invariant to test: Replay and vote handling must preserve forward progress for the honest heaviest path under bounded adversarial fork noise.
- Expected Immunefi impact: Medium. Temporary freezing of network transactions by delaying one block by 500% or more of the average block time of the preceding 24 hours beyond standard difficulty adjustments
- Fast validation: Run mixed honest/adversarial fork simulations and assert forward progress latency remains within design bounds.
