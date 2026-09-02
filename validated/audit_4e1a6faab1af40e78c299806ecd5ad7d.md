### Title
Cross-organization `Team` membership escalation via self-forged `membership` webhook - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` derives the signing organization from the payload's `organization.login` when no `repository` key is present, which is exactly the case for `membership` events. An attacker who owns their own GitHub organization (with a `Shipit.github_app`/`webhook_secret` they control) can therefore self-sign an arbitrary `membership` payload and have it accepted, then use `params.team.id` to target a `Team` record that actually belongs to a different, victim organization, adding an arbitrary GitHub login as a member of that team.

### Finding Description
The broken binding: `Team#organization` (as last legitimately set for `github_id = X`) must equal `params.organization.login` for any webhook accepted for that `github_id`, i.e. `Team.find_by(github_id: X).organization == params.organization.login`. This is never checked.

Path:
1. `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)`, and `repository_owner` is `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . `membership` payloads carry no `repository` key, so `repository_owner` resolves to `params.organization.login` — fully attacker-controlled.
2. If Shipit is configured multi-tenant (each org has its own `Shipit.github_app`/`webhook_secret`, as documented in `test/dummy/config/secrets_double_github_app.yml`), the attacker's own org has a `webhook_secret` the attacker legitimately knows (they own that org's GitHub App). `GitHubApp#verify_webhook_signature` just HMACs the raw body with that secret [2](#0-1) , so the attacker can compute a fully valid `X-Hub-Signature` for any JSON body they construct, as long as `organization.login` equals their own org.
3. `MembershipHandler#find_or_create_team!` looks the team up **only by `github_id`**, and only sets `team.organization` inside the `find_or_create_by!` block, which runs only on record creation, not on find [3](#0-2) . If a `Team` row with that `github_id` already exists (created earlier from a legitimate webhook/`Team.find_or_create_by_handle` for the real, victim organization), the lookup returns that existing record untouched — its `organization` attribute is never revalidated against `params.organization.login`.
4. `MembershipHandler#process` then calls `team.add_member(member)` where `member = User.find_or_create_by_login!(params.member.login)` [4](#0-3) , `params.member.login` being an arbitrary string chosen by the attacker (e.g. their own GitHub login), fetched via `Shipit.github.api.user(login)` [5](#0-4) .

Existing guards do not prevent this: `verify_signature` authenticates *an* organization's webhook, not that the organization matches the team being mutated; `find_or_create_by!(github_id:)` has no `organization:` constraint; the `ExplicitParameters` schema only validates types/presence, not cross-record consistency [6](#0-5) .

Exploit: attacker sends `POST /webhooks` with header `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with their own org's `webhook_secret`, and body `{"action":"added","team":{"id":<victim_team_github_id>,"name":"x","slug":"x","url":"x"},"organization":{"login":"<attacker-org>"},"member":{"login":"<attacker-github-login>"}}`. `<victim_team_github_id>` must be a `github_id` value that already exists in Shipit's `teams` table for a real, different organization — this happens whenever an operator has ever synced/created that team (e.g. via `Team.find_or_create_by_handle`, `bin/rake teams:fetch`, or a prior legitimate `membership` webhook).

### Impact Explanation
If the targeted `Team` is one of the entries configured in the operator's `Shipit.github_teams` (used by `User#authorized?` [7](#0-6) ), the attacker escalates an arbitrary GitHub account into Shipit's authorization set for that team without any legitimate membership in the victim's real GitHub organization/team. This is a High-severity escalation into `Shipit.github_teams` authorization, matching the rules' High category. It is repeatable against any known/guessable pre-existing `github_id` and does not require compromising any Shipit or GitHub secret belonging to the victim.

### Likelihood Explanation
Preconditions: (a) Shipit must be deployed in a multi-organization configuration where the attacker's own org has its own registered `Shipit.github_app`/`webhook_secret` (attacker legitimately controls this since they own that org's GitHub App); (b) the victim `Team` row must already exist in Shipit's database with a known `github_id` (numeric GitHub team ids for public/enumerable teams are discoverable via the GitHub API or prior observation). Attacker cost is a single crafted HTTP POST with a self-computed HMAC — no privileged credentials, sessions, or victim secrets are required. This is directly repeatable for any discoverable `github_id`.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup/creation by both `github_id` and `organization` (e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and reject/no-op the event (or raise) if a `Team` with that `github_id` already exists under a *different* `organization`. Additionally, harden `WebhooksController#verify_signature` so that events lacking a `repository` key (like `membership`) are verified against the specific organization whose team/records are being mutated, not an attacker-suppliable `organization.login` alone.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/membership_handler_test.rb (conceptual)
test "membership webhook does not let org B mutate org A's team by github_id collision" do
  team = Shipit::Team.create!(github_id: 999, organization: 'org-a', slug: 'core', name: 'Core', api_url: 'https://x')

  attacker_payload = {
    action: 'added',
    team: { id: 999, name: 'Core', slug: 'core', url: 'https://x' },
    organization: { login: 'org-b' }, # attacker-owned org, distinct from 'org-a'
    member: { login: 'attacker-login' }
  }

  # Binding under test, stated as equality BEFORE:
  assert_equal 'org-a', team.reload.organization

  Shipit::User.stubs(:find_or_create_by_login!).with('attacker-login').returns(shipit_users(:walrus))
  Shipit::Webhooks::Handlers::MembershipHandler.new.call(attacker_payload.deep_stringify_keys)

  # Binding AFTER: organization must remain 'org-a' (team not silently reassigned),
  # AND the attacker's user must NOT have been added to org-a's team, since the event
  # was signed for org-b, not org-a.
  assert_equal 'org-a', team.reload.organization
  refute_includes team.members, shipit_users(:walrus) # currently FAILS: attacker's user is added
end
```
This demonstrates that `Team.find_or_create_by!(github_id:)` performs no check of `params.organization.login` against the existing `Team#organization`, allowing a webhook legitimately signed for `org-b` to mutate membership of a team belonging to `org-a`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
