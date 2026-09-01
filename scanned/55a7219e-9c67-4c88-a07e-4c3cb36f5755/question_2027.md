# Q2027: `PYTHONSTARTUP` hijacks `python deploy.py` (python) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `python deploy.py` step, can an unprivileged fork PR author set `PYTHONSTARTUP` through a `machine.environment` entry in the fork branch's `shipit.yml` so the python process names a python file executed at interpreter start?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `PYTHONSTARTUP` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `python deploy.py`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `PYTHONSTARTUP` unfiltered into the `python deploy.py` subprocess, which names a python file executed at interpreter start
- Invariant to test: The `python deploy.py` subprocess inherits no fork-controllable environment key such as `PYTHONSTARTUP`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `python deploy.py` and injected `PYTHONSTARTUP`, assert Command#unbundled_env passes `PYTHONSTARTUP` to the spawned process.
