# Q5820: `GEM_HOME` hijacks `bundle install` (ruby/bundler) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `bundle install` step, can an unprivileged fork PR author set `GEM_HOME` through a `machine.environment` entry in the fork branch's `shipit.yml` so the ruby/bundler process redirects gem resolution to an attacker-populated gem tree?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `GEM_HOME` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `bundle install`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `GEM_HOME` unfiltered into the `bundle install` subprocess, which redirects gem resolution to an attacker-populated gem tree
- Invariant to test: The `bundle install` subprocess inherits no fork-controllable environment key such as `GEM_HOME`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `bundle install` and injected `GEM_HOME`, assert Command#unbundled_env passes `GEM_HOME` to the spawned process.
