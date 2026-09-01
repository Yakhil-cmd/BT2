# Q5926: Concrete `NODE_OPTIONS=--require /tmp/evil.js` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `NODE_OPTIONS` to `--require /tmp/evil.js` through a pull request label name (uppercased), so the review-stack deploy process executes it because it injects `--require /path/to/evil` so any node step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `NODE_OPTIONS=--require /tmp/evil.js` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `--require /tmp/evil.js` injects `--require /path/to/evil` so any node step loads attacker code
- Invariant to test: No spawned deploy process ever sees a fork-controlled `NODE_OPTIONS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `NODE_OPTIONS=--require /tmp/evil.js`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
