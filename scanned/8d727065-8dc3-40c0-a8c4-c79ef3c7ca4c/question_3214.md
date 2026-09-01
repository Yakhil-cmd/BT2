# Q3214: `SHELL` hijacks `make deploy` (make/shell) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `make deploy` step, can an unprivileged fork PR author set `SHELL` through a pull request label name (uppercased) so the make/shell process changes the shell binary used to interpret a step, redirecting execution to an attacker program?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `SHELL` via a pull request label name (uppercased), with the deploy spec step `make deploy`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `SHELL` unfiltered into the `make deploy` subprocess, which changes the shell binary used to interpret a step, redirecting execution to an attacker program
- Invariant to test: The `make deploy` subprocess inherits no fork-controllable environment key such as `SHELL`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `make deploy` and injected `SHELL`, assert Command#unbundled_env passes `SHELL` to the spawned process.
