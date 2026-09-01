# Q1802: `LD_PRELOAD` hijacks `kubectl apply -f k8s/` (shell) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `kubectl apply -f k8s/` step, can an unprivileged fork PR author set `LD_PRELOAD` through a pull request label name (uppercased) so the shell process preloads an attacker shared object into every process the deploy spawns?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `LD_PRELOAD` via a pull request label name (uppercased), with the deploy spec step `kubectl apply -f k8s/`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `LD_PRELOAD` unfiltered into the `kubectl apply -f k8s/` subprocess, which preloads an attacker shared object into every process the deploy spawns
- Invariant to test: The `kubectl apply -f k8s/` subprocess inherits no fork-controllable environment key such as `LD_PRELOAD`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `kubectl apply -f k8s/` and injected `LD_PRELOAD`, assert Command#unbundled_env passes `LD_PRELOAD` to the spawned process.
