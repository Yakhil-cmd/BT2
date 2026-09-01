# Q0504: Forged membership `removed` for team `shopify/sre`

## Question
Can an unprivileged attacker forge a `membership` webhook (`action: removed`) whose `team` resolves to the monitored handle `shopify/sre` and whose `member.login` is chosen by the attacker, so `MembershipHandler` writes the row `User#authorized?` trusts for `shopify/sre`?

## Target
- File/function: app/models/shipit/webhooks/handlers/membership_handler.rb + app/models/shipit/team.rb + app/models/shipit/user.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: `action: removed`, `team` fields resolving to `shopify/sre`, `member.login`
- Exploit idea: team identity is taken from the payload via `find_or_create_by!(github_id:)`; if `shopify/sre` is in `Shipit.github_teams`, the forged row grants/revokes UI access
- Invariant to test: A membership row for `shopify/sre` reflects real GitHub membership for that team.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: forge membership `removed` for `shopify/sre`, assert the target User#authorized? state changed.
