### Title
Cross-organization webhook forgery removes arbitrary team members via `Team.find_or_create_by!(github_id:)` lookup - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a request against using `repository_owner`, which for `membership` events falls back to `params.dig('organization', 'login')` [1](#0-0) [2](#0-1) . `MembershipHandler#process` then resolves the target `Team` purely by `params.team.id` (the numeric GitHub team ID) via `Team.find_or_create_by!(github_id: params.team.id)`, with no check that the found team's `organization` matches the org whose secret verified the signature [3](#0-2) . Because the org used for signature verification and the org used to scope the team mutation are the same attacker-controlled field (`params.organization.login`) only on first creation, but the lookup key (`github_id`) is a separate attacker-controlled field, an attacker who legitimately controls their own org's webhook secret can forge a `membership`/`removed` event naming a *different*, pre-existing team's `github_id` and any `member.login`, causing that team's membership to be mutated even though it belongs to an unrelated organization.

### Finding Description
The binding that should hold is: **verifying organization (derived from `params.organization.login`, used to pick the webhook secret in `Shipit.github(organization: repository_owner)`) == organization owning the `Team` record being mutated (`team.organization`, taken from the `Team` row identified by `params.team.id`)**.

Trace:
1. `WebhooksController#verify_signature` picks the secret via `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')`. For `membership` events, GitHub's payload has no top-level `repository`, so `repository_owner` resolves to `params.organization.login` — fully attacker-supplied JSON, only constrained by having to match a *registered* org in `Shipit.github_apps` [4](#0-3) .
2. The attacker sets `organization.login = 'OrgA'` (their own org, for which they legitimately hold the webhook secret), so `verify_webhook_signature` passes using OrgA's `webhook_secret` [5](#0-4) .
3. `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id)`. If a `Team` row already exists with that `github_id` (created earlier from a legitimate OrgB membership webhook), `find_or_create_by!` simply **finds** it and returns it — the block (which sets `team.organization = params.organization.login`) only executes on creation, and even when it does run there is no validation that it matches anything real [6](#0-5) .
4. `process` then runs `team.members.delete(member)` (or `team.add_member(member)`) on that OrgB team using `member.login`, which is also fully attacker-supplied and resolved via `User.find_or_create_by_login!` [7](#0-6) .

No code path re-derives or checks `team.organization` against the verifying org before performing the mutation — `find_or_create_team!` and `process` trust `params.team.id` and `params.member.login` unconditionally once the *global* signature check for whatever org name the attacker put in the JSON has passed. `drop_unhandled_event`, `ExplicitParameters` schema and `check_if_ping` only validate shape, not tenant ownership.

### Impact Explanation
An attacker who legitimately administers one GitHub organization onboarded to a shared/multi-tenant Shipit instance (i.e., holds that org's `webhook_secret` configured in `Shipit.github_apps`) can forge a `membership`/`removed` (or `added`) event that mutates the membership of a `Team` belonging to a *different* tenant organization, by simply guessing/observing that org's numeric GitHub team `github_id` and a target `member.login`. Since `Team` records back `Shipit.github_teams` authorization (`User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id))`) [8](#0-7) , removing a legitimate member from an authorization-granting team is a deploy-authorization downgrade for that member, and conversely `added` could be used to grant a chosen `member.login` team membership under the target org without that org's consent. This matches the "escalation into `Shipit.github_teams` authorization" High-severity category (a write to a record that did not authenticate for it). It is repeatable against any team whose `github_id` the attacker can discover (team IDs are visible on GitHub UI/API and not secret) and requires only one org's own webhook secret.

### Likelihood Explanation
Preconditions: (a) the Shipit deployment serves more than one GitHub organization (multi-tenant `Shipit.github_apps` config) — a documented/supported configuration; (b) the attacker administers/owns one such onboarded org and thus possesses that org's `webhook_secret`, which is a legitimate low-privilege capability, not a stolen secret; (c) the target team's `github_id` (a small integer, easily discoverable via GitHub's public team API/UI for teams the attacker can see or infer) must exist as a `Team` row in Shipit already (created by a prior legitimate `membership` event from OrgB). Attacker cost is a single crafted HTTP POST to `/webhooks` with a valid `X-Hub-Signature` computed with their own secret. This is straightforward and fully repeatable.

### Recommendation
In `MembershipHandler`, scope the team lookup by both `github_id` and the verifying organization, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)` (or explicitly reject the event if an existing team's `organization` does not match `params.organization.login`). More robustly, thread the already-verified `repository_owner`/organization from `WebhooksController` into the handler and assert `team.organization == verified_organization` before performing `add_member`/`delete` in `process`, raising/dropping the event otherwise.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership removed from OrgA-signed event mutates an OrgB-owned team" do
  org_b_team = Shipit::Team.create!(github_id: 999, organization: 'org-b', slug: 'deployers', name: 'Deployers', api_url: 'https://x')
  victim = Shipit::User.find_or_create_by_login!('org-b-victim')
  org_b_team.add_member(victim)

  Shipit.github(organization: 'org-a').stubs(:verify_webhook_signature).returns(true) # OrgA's own valid secret/signature

  @request.headers['X-Github-Event'] = 'membership'
  post :create, as: :json, body: {
    action: 'removed',
    team: { id: 999, name: 'Deployers', slug: 'deployers', url: 'https://x' },
    organization: { login: 'org-a' },   # verifying org != team's org ('org-b')
    member: { login: 'org-b-victim' }
  }.to_json

  assert_response :ok
  assert_not_includes org_b_team.reload.members, victim  # binding violated: OrgA-signed request mutated OrgB's team
end
```
This demonstrates the equality `verifying organization ('org-a') != team.organization ('org-b')` before the request, while the mutation still succeeds, proving the missing tenant-ownership check in `MembershipHandler#process`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
