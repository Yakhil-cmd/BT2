# Q2539: Concrete `GIT_TEMPLATE_DIR=/tmp/tmpl (with hooks/post-che` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `GIT_TEMPLATE_DIR` to `/tmp/tmpl (with hooks/post-checkout)` through a pull request label name (uppercased), so the review-stack deploy process executes it because it supplies a template dir whose hooks are copied into and run on the next `git clone`?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `GIT_TEMPLATE_DIR=/tmp/tmpl (with hooks/post-checkout)` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `/tmp/tmpl (with hooks/post-checkout)` supplies a template dir whose hooks are copied into and run on the next `git clone`
- Invariant to test: No spawned deploy process ever sees a fork-controlled `GIT_TEMPLATE_DIR`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `GIT_TEMPLATE_DIR=/tmp/tmpl (with hooks/post-checkout)`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
