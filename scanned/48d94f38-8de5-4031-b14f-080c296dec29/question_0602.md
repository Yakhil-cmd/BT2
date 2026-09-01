# Q0602: `LD_LIBRARY_PATH` hijacks `kubectl apply -f k8s/` (shell) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `kubectl apply -f k8s/` step, can an unprivileged fork PR author set `LD_LIBRARY_PATH` through a pull request label name (uppercased) so the shell process redirects dynamic linking to attacker libraries for spawned binaries?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `LD_LIBRARY_PATH` via a pull request label name (uppercased), with the deploy spec step `kubectl apply -f k8s/`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `LD_LIBRARY_PATH` unfiltered into the `kubectl apply -f k8s/` subprocess, which redirects dynamic linking to attacker libraries for spawned binaries
- Invariant to test: The `kubectl apply -f k8s/` subprocess inherits no fork-controllable environment key such as `LD_LIBRARY_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `kubectl apply -f k8s/` and injected `LD_LIBRARY_PATH`, assert Command#unbundled_env passes `LD_LIBRARY_PATH` to the spawned process.
