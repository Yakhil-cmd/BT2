# Q0141: `PYTHONPATH` hijacks `python deploy.py` (python) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `python deploy.py` step, can an unprivileged fork PR author set `PYTHONPATH` through a `machine.environment` entry in the fork branch's `shipit.yml` so the python process prepends an attacker module path so a python step imports attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `PYTHONPATH` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `python deploy.py`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `PYTHONPATH` unfiltered into the `python deploy.py` subprocess, which prepends an attacker module path so a python step imports attacker code
- Invariant to test: The `python deploy.py` subprocess inherits no fork-controllable environment key such as `PYTHONPATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `python deploy.py` and injected `PYTHONPATH`, assert Command#unbundled_env passes `PYTHONPATH` to the spawned process.
