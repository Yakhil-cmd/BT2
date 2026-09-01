# Q0484: `BASH_ENV` hijacks `bash script/release.sh` (bash) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `bash script/release.sh` step, can an unprivileged fork PR author set `BASH_ENV` through a pull request label name (uppercased) so the bash process names a file bash sources before running a non-interactive `shipit.yml` step?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `BASH_ENV` via a pull request label name (uppercased), with the deploy spec step `bash script/release.sh`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `BASH_ENV` unfiltered into the `bash script/release.sh` subprocess, which names a file bash sources before running a non-interactive `shipit.yml` step
- Invariant to test: The `bash script/release.sh` subprocess inherits no fork-controllable environment key such as `BASH_ENV`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `bash script/release.sh` and injected `BASH_ENV`, assert Command#unbundled_env passes `BASH_ENV` to the spawned process.
