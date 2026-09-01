# Q1464: `GEM_PATH` hijacks `bundle install` (ruby/bundler) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `bundle install` step, can an unprivileged fork PR author set `GEM_PATH` through a pull request label name (uppercased) so the ruby/bundler process adds an attacker gem path consulted by `require`/`bundle`?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `GEM_PATH` via a pull request label name (uppercased), with the deploy spec step `bundle install`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `GEM_PATH` unfiltered into the `bundle install` subprocess, which adds an attacker gem path consulted by `require`/`bundle`
- Invariant to test: The `bundle install` subprocess inherits no fork-controllable environment key such as `GEM_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `bundle install` and injected `GEM_PATH`, assert Command#unbundled_env passes `GEM_PATH` to the spawned process.
