# Q4934: Concrete `PATH=./bin:/usr/bin` payload via a pull request label name (uppercased)

## Question
Can an unprivileged fork PR set `PATH` to `./bin:/usr/bin` through a pull request label name (uppercased), so the review-stack deploy process executes it because it prepends an attacker-controlled directory so a bare command name in a `shipit.yml` step resolves to an attacker binary?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `PATH=./bin:/usr/bin` via a pull request label name (uppercased)
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; the concrete value `./bin:/usr/bin` prepends an attacker-controlled directory so a bare command name in a `shipit.yml` step resolves to an attacker binary
- Invariant to test: No spawned deploy process ever sees a fork-controlled `PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `PATH=./bin:/usr/bin`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
