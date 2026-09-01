# Q2347: `PYTHONPATH` hijacks `pip install -r requirements.txt` (python) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `pip install -r requirements.txt` step, can an unprivileged fork PR author set `PYTHONPATH` through a pull request label name (uppercased) so the python process prepends an attacker module path so a python step imports attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `PYTHONPATH` via a pull request label name (uppercased), with the deploy spec step `pip install -r requirements.txt`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `PYTHONPATH` unfiltered into the `pip install -r requirements.txt` subprocess, which prepends an attacker module path so a python step imports attacker code
- Invariant to test: The `pip install -r requirements.txt` subprocess inherits no fork-controllable environment key such as `PYTHONPATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `pip install -r requirements.txt` and injected `PYTHONPATH`, assert Command#unbundled_env passes `PYTHONPATH` to the spawned process.
