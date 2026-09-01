# Q2299: `RUBYLIB` hijacks `rake deploy` (ruby) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `rake deploy` step, can an unprivileged fork PR author set `RUBYLIB` through a pull request label name (uppercased) so the ruby process prepends an attacker load path so `require` in a ruby step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `RUBYLIB` via a pull request label name (uppercased), with the deploy spec step `rake deploy`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `RUBYLIB` unfiltered into the `rake deploy` subprocess, which prepends an attacker load path so `require` in a ruby step loads attacker code
- Invariant to test: The `rake deploy` subprocess inherits no fork-controllable environment key such as `RUBYLIB`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `rake deploy` and injected `RUBYLIB`, assert Command#unbundled_env passes `RUBYLIB` to the spawned process.
