# Q1390: `PATH` hijacks `yarn install` (node) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `yarn install` step, can an unprivileged fork PR author set `PATH` through a pull request label name (uppercased) so the node process prepends an attacker-controlled directory so a bare command name in a `shipit.yml` step resolves to an attacker binary?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `PATH` via a pull request label name (uppercased), with the deploy spec step `yarn install`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `PATH` unfiltered into the `yarn install` subprocess, which prepends an attacker-controlled directory so a bare command name in a `shipit.yml` step resolves to an attacker binary
- Invariant to test: The `yarn install` subprocess inherits no fork-controllable environment key such as `PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `yarn install` and injected `PATH`, assert Command#unbundled_env passes `PATH` to the spawned process.
