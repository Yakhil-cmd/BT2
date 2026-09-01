# Q3378: Forged `membership` webhook (added to a monitored team) rewrites Shipit authorization

## Question
Can an unprivileged attacker POST a `membership` webhook that sets `action: added`, `team.id` to a team id present in `Shipit.github_teams`, and `member.login` to the attacker's GitHub login, so `MembershipHandler#process` writes a `Membership` row that `User#authorized?` then trusts, granting or revoking access to the Shipit UI?

## Target
- File/function: app/models/shipit/webhooks/handlers/membership_handler.rb + app/models/shipit/user.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: `action`, `team.{id,slug,name,url}`, `organization.login`, `member.login`; attacker sets `action: added`, `team.id` to a team id present in `Shipit.github_teams`, and `member.login` to the attacker's GitHub login
- Exploit idea: `MembershipHandler` derives the whole team+member identity from the payload; `User#authorized?` is `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, so a forged membership row is a full authorization grant
- Invariant to test: A membership row for a team in Shipit.github_teams reflects a membership GitHub actually reports for that team.
- Expected Immunefi impact: High — Privilege escalation into Shipit.github_teams authorization
- Fast validation: minitest: process a forged membership `added` payload, then assert the attacker User#authorized? is true (or a victim's became false).
