# Q3247: `NODE_OPTIONS` hijacks `npm ci` (node) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `npm ci` step, can an unprivileged fork PR author set `NODE_OPTIONS` through a pull request label name (uppercased) so the node process injects `--require /path/to/evil` so any node step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `NODE_OPTIONS` via a pull request label name (uppercased), with the deploy spec step `npm ci`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `NODE_OPTIONS` unfiltered into the `npm ci` subprocess, which injects `--require /path/to/evil` so any node step loads attacker code
- Invariant to test: The `npm ci` subprocess inherits no fork-controllable environment key such as `NODE_OPTIONS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `npm ci` and injected `NODE_OPTIONS`, assert Command#unbundled_env passes `NODE_OPTIONS` to the spawned process.
