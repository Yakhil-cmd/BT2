# Q5434: Concrete `LD_PRELOAD=/dev/shm/x.so` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `LD_PRELOAD` to `/dev/shm/x.so` through a pull request label name (uppercased), so the review-stack deploy process executes it because it preloads an attacker shared object into every process the deploy spawns?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `LD_PRELOAD=/dev/shm/x.so` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `/dev/shm/x.so` preloads an attacker shared object into every process the deploy spawns
- Invariant to test: No spawned deploy process ever sees a fork-controlled `LD_PRELOAD`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `LD_PRELOAD=/dev/shm/x.so`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
