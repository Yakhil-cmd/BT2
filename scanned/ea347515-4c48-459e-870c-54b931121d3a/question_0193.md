# Q0193: Concrete `PYTHONPATH=.` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `PYTHONPATH` to `.` through a pull request label name (uppercased), so the review-stack deploy process executes it because it prepends an attacker module path so a python step imports attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `PYTHONPATH=.` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `.` prepends an attacker module path so a python step imports attacker code
- Invariant to test: No spawned deploy process ever sees a fork-controlled `PYTHONPATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `PYTHONPATH=.`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
