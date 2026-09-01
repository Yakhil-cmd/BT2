# Q2877: `PYTHONSTARTUP` hijacks `python deploy.py` (python) via a pull request label name (uppercased)

## Question
When a review stack's deploy runs the `python deploy.py` step, can an unprivileged fork PR author set `PYTHONSTARTUP` through a pull request label name (uppercased) so the python process names a python file executed at interpreter start?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `PYTHONSTARTUP` via a pull request label name (uppercased), with the deploy spec step `python deploy.py`
- Exploit idea: `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |n,h| h[n.upcase]='true' }` with no key allowlist, and `LabelCapturingHandler#capture_labels` persists those names straight from the webhook body; `Command#unbundled_env` carries `PYTHONSTARTUP` unfiltered into the `python deploy.py` subprocess, which names a python file executed at interpreter start
- Invariant to test: The `python deploy.py` subprocess inherits no fork-controllable environment key such as `PYTHONSTARTUP`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `python deploy.py` and injected `PYTHONSTARTUP`, assert Command#unbundled_env passes `PYTHONSTARTUP` to the spawned process.
