# Q4818: Concrete `GIT_ASKPASS=/proc/self/cwd/askpass` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `GIT_ASKPASS` to `/proc/self/cwd/askpass` through a pull request label name (uppercased), so the review-stack deploy process executes it because it points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `GIT_ASKPASS=/proc/self/cwd/askpass` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `/proc/self/cwd/askpass` points git's credential helper at an attacker script that runs during `git fetch`/`git clone` in StackCommands
- Invariant to test: No spawned deploy process ever sees a fork-controlled `GIT_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `GIT_ASKPASS=/proc/self/cwd/askpass`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
