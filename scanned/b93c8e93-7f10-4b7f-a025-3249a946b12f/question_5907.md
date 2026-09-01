# Q5907: double-escaping / no-escape of interpolated value in shipit.yml `deploy.variables`

## Question
Can an unprivileged fork PR author abuse the `deploy.variables` section of the review-stack `shipit.yml` so that a task/deploy env VALUE contains shell-significant characters that survive `Shellwords.escape` semantics when re-embedded, defeating the assumption that the bytes handed to the shell differ from the literal step string authored in shipit.yml?

## Target
- File/function: app/models/shipit/deploy_spec.rb + app/models/shipit/deploy_spec/file_system.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the `deploy.variables` content on the fork branch (a task/deploy env VALUE contains shell-significant characters that survive `Shellwords.escape` semantics when re-embedded)
- Exploit idea: `DeploySpec` reads `deploy.variables` from the fork-authored shipit.yml and feeds it into command building where the bytes handed to the shell differ from the literal step string authored in shipit.yml
- Invariant to test: Every value read from a fork-authored shipit.yml is treated as untrusted and cannot alter the executed argv or leak Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build a DeploySpec whose `deploy.variables` carries the payload, run through Command building, assert the argv/leak.
