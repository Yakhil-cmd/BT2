# Q5792: Concrete `PYTHONPATH=.` payload via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
Can an unprivileged fork PR set `PYTHONPATH` to `.` through a `machine.environment` entry in the fork branch's `shipit.yml`, so the review-stack deploy process executes it because it prepends an attacker module path so a python step imports attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> PTY.spawn
- Attacker controls: `PYTHONPATH=.` via a `machine.environment` entry in the fork branch's `shipit.yml`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the concrete value `.` prepends an attacker module path so a python step imports attacker code
- Invariant to test: No spawned deploy process ever sees a fork-controlled `PYTHONPATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: inject `PYTHONPATH=.`, assert Command#unbundled_env carries it verbatim to PTY.spawn.
