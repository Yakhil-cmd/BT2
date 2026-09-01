# Q1393: Concrete `RUBYOPT=-r/tmp/evil` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `RUBYOPT` to `-r/tmp/evil` through a pull request label name (uppercased), so the review-stack deploy process executes it because it injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `RUBYOPT=-r/tmp/evil` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `-r/tmp/evil` injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup
- Invariant to test: No spawned deploy process ever sees a fork-controlled `RUBYOPT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `RUBYOPT=-r/tmp/evil`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
