# Q1251: Forged `membership` webhook (org spoof) rewrites Shipit authorization

## Question
Can an unprivileged attacker POST a `membership` webhook that sets `organization.login` and `team.slug` so the created team's handle matches a configured oauth team, so `MembershipHandler#process` writes a `Membership` row that `User#authorized?` then trusts, granting or revoking access to the Shipit UI?

## Target
- File/function: app/models/shipit/webhooks/handlers/membership_handler.rb + app/models/shipit/user.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: `action`, `team.{id,slug,name,url}`, `organization.login`, `member.login`; attacker sets `organization.login` and `team.slug` so the created team's handle matches a configured oauth team
- Exploit idea: `MembershipHandler` derives the whole team+member identity from the payload; `User#authorized?` is `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, so a forged membership row is a full authorization grant
- Invariant to test: A membership row for a team in Shipit.github_teams reflects a membership GitHub actually reports for that team.
- Expected Immunefi impact: High — Privilege escalation into Shipit.github_teams authorization
- Fast validation: minitest: process a forged membership `added` payload, then assert the attacker User#authorized? is true (or a victim's became false).
