# Q5245: `RUBYOPT` hijacks `rake deploy` (ruby) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `rake deploy` step, can an unprivileged fork PR author set `RUBYOPT` through a pull request label name (uppercased) so the ruby process injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `RUBYOPT` via a pull request label name (uppercased), with the deploy spec step `rake deploy`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `RUBYOPT` unfiltered into the `rake deploy` subprocess, which injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup
- Invariant to test: The `rake deploy` subprocess inherits no fork-controllable environment key such as `RUBYOPT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `rake deploy` and injected `RUBYOPT`, assert Command#unbundled_env passes `RUBYOPT` to the spawned process.
