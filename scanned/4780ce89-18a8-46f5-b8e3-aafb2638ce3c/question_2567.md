# Q2567: Forged membership `added` for team `myorg/shipit-admins`

## Question
Can an unprivileged attacker forge a `membership` webhook (`action: added`) whose `team` resolves to the monitored handle `myorg/shipit-admins` and whose `member.login` is chosen by the attacker, so `MembershipHandler` writes the row `User#authorized?` trusts for `myorg/shipit-admins`?

## Target
- File/function: app/models/shipit/webhooks/handlers/membership_handler.rb + app/models/shipit/team.rb + app/models/shipit/user.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: `action: added`, `team` fields resolving to `myorg/shipit-admins`, `member.login`
- Exploit idea: team identity is taken from the payload via `find_or_create_by!(github_id:)`; if `myorg/shipit-admins` is in `Shipit.github_teams`, the forged row grants/revokes UI access
- Invariant to test: A membership row for `myorg/shipit-admins` reflects real GitHub membership for that team.
- Expected Immunefi impact: High — Privilege escalation into Shipit.github_teams authorization
- Fast validation: minitest: forge membership `added` for `myorg/shipit-admins`, assert the target User#authorized? state changed.
