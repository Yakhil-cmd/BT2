# Q1054: `RUBYOPT` hijacks `bundle install` (ruby/bundler) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `bundle install` step, can an unprivileged fork PR author set `RUBYOPT` through a pull request label name (uppercased) so the ruby/bundler process injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `RUBYOPT` via a pull request label name (uppercased), with the deploy spec step `bundle install`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `RUBYOPT` unfiltered into the `bundle install` subprocess, which injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup
- Invariant to test: The `bundle install` subprocess inherits no fork-controllable environment key such as `RUBYOPT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `bundle install` and injected `RUBYOPT`, assert Command#unbundled_env passes `RUBYOPT` to the spawned process.
