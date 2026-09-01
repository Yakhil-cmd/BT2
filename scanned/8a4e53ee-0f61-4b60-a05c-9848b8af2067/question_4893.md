# Q4893: `IFS` hijacks `bash script/release.sh` (bash) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `bash script/release.sh` step, can an unprivileged fork PR author set `IFS` through a `machine.environment` entry in the fork branch's `shipit.yml` so the bash process changes the shell field separator so a step string re-splits into attacker-chosen argv?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `IFS` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `bash script/release.sh`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `IFS` unfiltered into the `bash script/release.sh` subprocess, which changes the shell field separator so a step string re-splits into attacker-chosen argv
- Invariant to test: The `bash script/release.sh` subprocess inherits no fork-controllable environment key such as `IFS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `bash script/release.sh` and injected `IFS`, assert Command#unbundled_env passes `IFS` to the spawned process.
