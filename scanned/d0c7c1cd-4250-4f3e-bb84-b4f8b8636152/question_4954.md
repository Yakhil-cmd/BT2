# Q4954: Concrete `BASH_ENV=/tmp/evil.sh` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `BASH_ENV` to `/tmp/evil.sh` through a pull request label name (uppercased), so the review-stack deploy process executes it because it names a file bash sources before running a non-interactive `shipit.yml` step?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `BASH_ENV=/tmp/evil.sh` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `/tmp/evil.sh` names a file bash sources before running a non-interactive `shipit.yml` step
- Invariant to test: No spawned deploy process ever sees a fork-controlled `BASH_ENV`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `BASH_ENV=/tmp/evil.sh`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
