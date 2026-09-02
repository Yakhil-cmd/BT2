### Title
`MembershipHandler#find_or_create_team!` skips organization ownership check on find, allowing cross-organization team membership escalation - ([File: app/models/shipit/team.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` looks up a `Team` by `github_id` only, and only sets/validates `team.organization` inside the `find_or_create_by!` creation block, which never runs when the team already exists. [1](#0-0)  This means once a `Team` record exists for a given `github_id`, any subsequent `membership` webhook that is verified for a *different* organization but reuses that same `team.id` will still resolve to the existing victim `Team` object and call `team.add_member(member)` on it, without ever comparing `params.organization.login` to the persisted `team.organization`. [2](#0-1) 

### Finding Description
The broken binding is: `team.organization` (persisted at creation time, e.g. `'victim-org'`) **should** equal the verified organization of the current webhook request (`params.organization.login`) before `team.add_member`/`team.members.delete` executes, but the code never performs this comparison on the "find" branch.

Code path:
- `WebhooksController#verify_signature` resolves the GitHub App config for `repository_owner` (falls back to `params.dig('organization','login')` for membership events) and calls `github_app.verify_webhook_signature(signature, raw_body)`. [3](#0-2) 
- `GitHubApp#verify_webhook_signature` is keyed per-organization: `return true unless webhook_secret` — i.e., verification always succeeds for any organization whose Shipit GitHub App config entry has no `webhook_secret` set. [4](#0-3)  This is a documented, valid configuration state (`config/secrets.development.example.yml` explicitly shows `webhook_secret: # nil` as a normal default), so a multi-org Shipit deployment can legitimately contain an "unsecured" organization entry. [5](#0-4) 
- Once the request passes `verify_signature` (as `attacker-org`), `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login; ... }`. The block (which sets `organization`) only runs on **creation**. If a `Team` row already exists for that `github_id` (e.g. previously created for `victim-org`), `find_or_create_by!` returns the existing record untouched, and `team.organization` remains `'victim-org'` even though the request was verified for `'attacker-org'`. [6](#0-5) 
- `process` then unconditionally does `team.add_member(member)` (for action `'added'`) using the attacker-supplied `params.member.login`, appending an arbitrary GitHub-login-derived `User` to the victim team's `members`. [7](#0-6) 

No other guard intervenes: `drop_unhandled_event`/`check_if_ping` do not check org identity, `ExplicitParameters` schema only validates types/presence (not cross-field consistency), and there is no `require_permission!`/`User#authorized?` check on this controller since it is `ActionController::Base` (not app auth) gated only by webhook signature.

### Impact Explanation
A successful exploit lets an attacker inject an arbitrary GitHub login as a member of a `Team` object that Shipit associates with a victim organization. If that `Team` is included in `Shipit.github_teams` (used for OAuth `teams:` restriction, see `Shipit#github_teams`), the attacker escalates an arbitrary chosen GitHub account into a Shipit-authorized team, which is used to gate application login/authorization. This is a genuine authorization-boundary violation across tenants/organizations in a multi-org Shipit install, matching the High severity category ("escalation into `Shipit.github_teams` authorization").

### Likelihood Explanation
Exploitability strictly depends on this Shipit instance being configured with multiple GitHub organizations (`github_app_config`/multi-org schema) where at least one configured organization entry has no `webhook_secret` set, so that `verify_webhook_signature` unconditionally returns `true` for that org's requests, per `return true unless webhook_secret`. [8](#0-7)  Given that precondition, the attacker needs no secrets: they can POST a crafted `membership` webhook JSON body (with `organization.login` set to the unsecured org, and `team.id` set to the victim team's known/guessed `github_id`) directly to `/webhooks` with any `X-Hub-Signature` value (or none) and it will pass. The victim's `github_id` is a GitHub-assigned team ID that must be known or guessed by the attacker, which is the main practical friction; however, once discovered, the attack is trivially repeatable against that team for arbitrary attacker-controlled `member.login` values.

### Recommendation
In `MembershipHandler#find_or_create_team!`/`#process`, after resolving the `Team`, explicitly verify `team.organization == params.organization.login` and reject/log (e.g., raise or no-op) if they differ, instead of relying on the `find_or_create_by!` block only firing on creation. Additionally, harden `GitHubApp#verify_webhook_signature` so that a missing `webhook_secret` fails closed (returns `false`/refuses) rather than defaulting to `true`, or require operators to always configure a `webhook_secret` per organization.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb`, no live GitHub calls):
1. Fixture: create/reuse `shipit_teams(:shopify_developers)` with `organization: 'shopify'`, `github_id: <known id>`.
2. Configure a second GitHub org (`'attacker-org'`) in the test secrets with no `webhook_secret` (or stub `Shipit.github(organization: 'attacker-org').webhook_secret` to return blank), so `verify_webhook_signature` for that org returns `true` unconditionally.
3. POST to `/webhooks` with `X-Github-Event: membership`, body:
   `{ action: 'added', team: { id: shipit_teams(:shopify_developers).github_id, name: 'x', slug: 'x', url: 'http://x' }, organization: { login: 'attacker-org' }, member: { login: 'attacker-chosen-login' }, repository: { owner: { login: 'attacker-org' } } }`.
4. Assert binding before: `shipit_teams(:shopify_developers).organization == 'shopify'` and request org == `'attacker-org'` (mismatch).
5. Assert `Membership.count` increases by 1, and `shipit_teams(:shopify_developers).members.map(&:login)` includes `'attacker-chosen-login'`, proving the victim team (`organization: 'shopify'`) received a membership write from a request verified for `'attacker-org'`.
6. Assert `assert_response :ok`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```
