# Q0026: Forged membership `removed` for team `shopify/admins`

## Question
Can an unprivileged attacker forge a `membership` webhook (`action: removed`) whose `team` resolves to the monitored handle `shopify/admins` and whose `member.login` is chosen by the attacker, so `MembershipHandler` writes the row `User#authorized?` trusts for `shopify/admins`?

## Target
- File/function: app/models/shipit/webhooks/handlers/membership_handler.rb + app/models/shipit/team.rb + app/models/shipit/user.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: `action: removed`, `team` fields resolving to `shopify/admins`, `member.login`
- Exploit idea: team identity is taken from the payload via `find_or_create_by!(github_id:)`; if `shopify/admins` is in `Shipit.github_teams`, the forged row grants/revokes UI access
- Invariant to test: A membership row for `shopify/admins` reflects real GitHub membership for that team.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: forge membership `removed` for `shopify/admins`, assert the target User#authorized? state changed.
