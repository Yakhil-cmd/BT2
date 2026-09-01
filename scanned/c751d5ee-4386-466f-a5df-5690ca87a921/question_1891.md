# Q1891: Forged membership `added` for team `org/owners`

## Question
Can an unprivileged attacker forge a `membership` webhook (`action: added`) whose `team` resolves to the monitored handle `org/owners` and whose `member.login` is chosen by the attacker, so `MembershipHandler` writes the row `User#authorized?` trusts for `org/owners`?

## Target
- File/function: app/models/shipit/webhooks/handlers/membership_handler.rb + app/models/shipit/team.rb + app/models/shipit/user.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: `action: added`, `team` fields resolving to `org/owners`, `member.login`
- Exploit idea: team identity is taken from the payload via `find_or_create_by!(github_id:)`; if `org/owners` is in `Shipit.github_teams`, the forged row grants/revokes UI access
- Invariant to test: A membership row for `org/owners` reflects real GitHub membership for that team.
- Expected Immunefi impact: High — Privilege escalation into Shipit.github_teams authorization
- Fast validation: minitest: forge membership `added` for `org/owners`, assert the target User#authorized? state changed.
