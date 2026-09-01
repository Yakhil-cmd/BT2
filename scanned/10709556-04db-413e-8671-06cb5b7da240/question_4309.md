# Q4309: Concrete `BUNDLE_GEMFILE=/tmp/Gemfile.evil` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `BUNDLE_GEMFILE` to `/tmp/Gemfile.evil` through a pull request label name (uppercased), so the review-stack deploy process executes it because it points bundler at an attacker Gemfile whose evaluated code runs?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `BUNDLE_GEMFILE=/tmp/Gemfile.evil` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `/tmp/Gemfile.evil` points bundler at an attacker Gemfile whose evaluated code runs
- Invariant to test: No spawned deploy process ever sees a fork-controlled `BUNDLE_GEMFILE`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `BUNDLE_GEMFILE=/tmp/Gemfile.evil`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
