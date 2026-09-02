## Analysis

Confirmed root cause: `User#authorized?` gates authenticated access on team membership: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [1](#0-0) , and `Shipit::Webhooks::Handlers::MembershipHandler#process` mutates `Team`/`Membership` rows purely from webhook JSON, with no reference to the verified signature's organization context: it does `team.add_member(member)` or `team.members.delete(member)` based solely on `params.action`, `params.team.id`, and `params.member.login` [2](#0-1) .

The binding that breaks is: **organization/secret that authenticates the webhook request** (chosen via `Shipit.github(organization: repository_owner)`) **versus the trust decision actually recorded** (`Team` membership rows that gate `Shipit.github_teams` authorization) — and crucially, this binding collapses entirely when `webhook_secret` is unset, since `verify_webhook_signature` unconditionally returns `true`:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [3](#0-2) 

`webhook_secret` is documented as **optional** in the setup guide [4](#0-3) , and the dummy/test configs ship with it unset (`webhook_secret: # nil`) [5](#0-4) . Any deployment that follows the documented "optional" guidance and omits it accepts **unsigned, unauthenticated** POSTs to `/webhooks` from anyone on the internet — `WebhooksController` has no other authentication (`skip_before_action :verify_authenticity_token`) [6](#0-5) .

With signature verification neutralized, an unprivileged internet attacker can POST a forged `membership` event: `Team.find_or_create_by!(github_id: params.team.id)` will match an existing, legitimately-synced authorization team (e.g. one listed in `Shipit.github_teams`, populated via `bin/rake teams:fetch`) if the attacker guesses/knows its numeric GitHub team `id` (discoverable via GitHub's public API for many orgs/teams), then `team.add_member(User.find_or_create_by_login!(params.member.login))` grants that arbitrary login membership in the authorizing team [7](#0-6) . Since `User#authorized?` checks exactly `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [1](#0-0) , this forged membership silently escalates any attacker-controlled `User` row into the authorized team, bypassing the GitHub OAuth/team-authorization boundary entirely — matching the "escalation into `Shipit.github_teams` authorization" High-impact category.

This is a direct structural analog of the report's bug class: a field (webhook payload / team membership) is acted upon (state mutated, authorization granted) without ever being covered by a valid verified signature, because the signature check is a no-op when the secret is absent — exactly like `voluntaryExit` acting on unvalidated pubkeys.

### Title
Unauthenticated webhook processing when `webhook_secret` is unset allows forged `membership` events to escalate arbitrary users into `Shipit.github_teams` authorization - (File: lib/shipit/github_app.rb)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever no `webhook_secret` is configured for an organization, and the setup documentation explicitly describes `webhook_secret` as optional. In that documented configuration, `WebhooksController` accepts and processes arbitrary unsigned webhook payloads, including `membership` events that directly mutate `Team`/`Membership` records used for authorization.

### Finding Description
`WebhooksController#verify_signature` picks a `GitHubApp` instance by `repository_owner` parsed straight out of the unauthenticated JSON body, then calls `verify_webhook_signature`, which short-circuits to `true` when `webhook_secret` is blank [3](#0-2) . No other authentication guards `/webhooks` (`skip_before_action :verify_authenticity_token`) [8](#0-7) .

`MembershipHandler#process` then trusts the body fully: it finds-or-creates a `Team` by the attacker-supplied `github_id`, and adds/removes an attacker-supplied `member.login` as a `User` from that team, with no verification that this request actually originated from GitHub or from the claimed organization [7](#0-6) .

`User#authorized?` uses exactly this `teams` association to gate access when `Shipit.github_teams` is configured [1](#0-0) .

### Impact Explanation
This breaks the equality: `organization whose secret authenticated the request == organization whose Team/Membership authorization state is written`. When no secret is set, the left side is empty (nothing authenticates), yet the right side is still fully writable by anyone. The consequence is escalation into `Shipit.github_teams` authorization — an explicitly listed High-impact outcome — since forging one `membership` webhook lets an attacker add an arbitrary `User` (which they also control via `login`) to a team that satisfies `Shipit.authorized?` checks, without ever having valid GitHub OAuth credentials or team membership.

### Likelihood Explanation
Likelihood depends on the deployment omitting `webhook_secret`. This is realistic because it's documented as optional (not merely unset-by-default in a template) [4](#0-3) , and the shipped test/dummy configs demonstrate this exact pattern of leaving it nil [9](#0-8) . No credentials, GitHub App private key, or session are needed by the attacker — only network access to the public `/webhooks` endpoint and knowledge/guessing of an existing team's numeric GitHub `id`.

### Recommendation
Reject webhook requests outright (fail closed) when `webhook_secret` is not configured for an organization, rather than treating a missing secret as "verification passed." Additionally, `MembershipHandler` (and other handlers) should cross-check `params.organization.login` against the organization actually used to authenticate the request, rather than trusting body-derived identifiers alone.

### Proof of Concept
1. Deploy Shipit with a GitHub org configured per the documented optional setting, i.e. `webhook_secret` left blank in `config/secrets.yml`, mirroring `test/dummy/config/secrets.yml` [9](#0-8) .
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": <id of an authorized team>, "name": "Shipit/team", "slug": "team", "url": "https://example.com"},
  "organization": {"login": "victim-org"},
  "member": {"login": "attacker-login"}
}
```
No `X-Hub-Signature` header is required — `verify_webhook_signature` returns `true` because `webhook_secret` is blank [10](#0-9) .
3. `MembershipHandler#process` creates/updates the `Team` and adds `User.find_or_create_by_login!("attacker-login")` as a member [2](#0-1) .
4. If `attacker-login` subsequently authenticates via OAuth, `User#authorized?` now returns `true` due to the forged team membership [1](#0-0) , granting them access gated by `Shipit.github_teams`.

### Citations

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** test/dummy/config/secrets.yml (L8-13)
```yaml
  github:
    domain: # defaults to github.com
    app_id: 42
    installation_id: 43
    bot_login: "shipit[bot]"
    webhook_secret: # nil
```

**File:** app/controllers/shipit/webhooks_controller.rb (L4-16)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

```
