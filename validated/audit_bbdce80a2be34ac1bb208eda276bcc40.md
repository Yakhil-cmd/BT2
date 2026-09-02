### Title
Cross-organization `Team` write via divergent org fields in webhook verification vs. `MembershipHandler` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#repository_owner` selects which org's `GitHubApp` verifies the HMAC signature by reading `repository.owner.login`, falling back to `organization.login` only if the former is absent. `MembershipHandler#find_or_create_team!`, however, unconditionally reads `params.organization.login` to stamp the new `Team#organization`. When both keys are present in a single payload with different values, the signature is verified against one org while the `Team` row is written for a different org.

### Finding Description
The binding the code implicitly assumes is: `org verified by GithubApp.verify_webhook_signature == org written to Team#organization`. This holds only when `repository.owner.login == organization.login` (or one is absent). It is broken as follows:

- `app/controllers/shipit/webhooks_controller.rb:59-62` — `repository_owner` returns `params.dig('repository','owner','login') || params.dig('organization','login')`. [1](#0-0) 
- `app/controllers/shipit/webhooks_controller.rb:24-30` — `verify_signature` fetches `Shipit.github(organization: repository_owner)` and verifies the raw body HMAC against *that* org's `webhook_secret`. [2](#0-1) 
- `app/models/shipit/webhooks/handlers/membership_handler.rb:38-43` — `find_or_create_team!` creates the `Team` and sets `team.organization = params.organization.login`, independent of `repository_owner`. [3](#0-2) 

An attacker who submits a payload with `repository.owner.login = "attacker-org"` and `organization.login = "victim-org"` causes verification to run against `attacker-org`'s `webhook_secret` (an org whose secret the attacker legitimately has, being that org's own GitHub App/webhook administrator) while `Team.find_or_create_by!` persists a new `Team` row (or matches an existing `github_id`) with `organization = "victim-org"` — an org the attacker never authenticated against.

Existing guards do not stop this: `verify_signature` only checks the HMAC of the raw body against `Shipit.github(organization: repository_owner)`, and never cross-checks that `organization.login` (used later by the handler) matches `repository_owner`. The `ExplicitParameters` schema on `MembershipHandler` (`app/models/shipit/webhooks/handlers/membership_handler.rb:7-21`) only enforces types/presence, not cross-field consistency. [4](#0-3) 

### Impact Explanation
A `Team` row can be created/attributed to an organization (`victim-org`) that never signed or authorized the request; only the attacker's own org's webhook secret was used for verification. This is a same-request cross-tenant mutation of the `Team` table (organization field), matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The blast radius is bounded to `Team#organization` values (which subsequently influence `Shipit.github(organization:)` lookups such as `refresh_members!` and `github_hooks` association keyed on `organization`) — so poisoning this field could misdirect later organization-scoped GitHub API calls for that Team. [5](#0-4) 

### Likelihood Explanation
Exploitation requires the attacker to control (know the `webhook_secret` of) at least one org that is configured in Shipit's multi-tenant `secrets.github` config — i.e., they must be a legitimate customer/org owner who has integrated their own org with this Shipit instance (matching the "emit webhooks from a repository/org they own" attacker capability). Genuine GitHub-triggered `membership` events do not naturally include a `repository` key with an arbitrary org, so the attacker must construct/sign the raw JSON body themselves using their own known secret and POST it directly to `/webhooks`, setting `repository.owner.login` to their own org and `organization.login` to the victim org. This is feasible without any Shipit session, API token, or GitHub App private key beyond the attacker's own org's webhook secret.

### Recommendation
In `MembershipHandler#find_or_create_team!`, derive/validate the org against the same value used for signature verification (`repository_owner`), or have `verify_signature` reject payloads where `params.dig('organization','login')` and `params.dig('repository','owner','login')` are both present but differ. At minimum, `find_or_create_team!` should use the verified `repository_owner` value rather than trusting `params.organization.login` independently.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative, not to be placed under test/ per scope rules)
test ":membership stamps organization from unverified organization.login, divergent from verified repository_owner" do
  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  payload = {
    action: 'added',
    team: { id: 999_999, name: 'x', slug: 'x', url: 'http://example.com' },
    organization: { login: 'victim-org' },
    member: { login: 'walrus' },
    repository: { owner: { login: 'attacker-org' } }
  }.to_json

  @request.headers['X-Github-Event'] = 'membership'
  assert_difference -> { Shipit::Team.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  team = Shipit::Team.find_by(github_id: 999_999)
  # Binding broken: verified org ('attacker-org') != written org ('victim-org')
  assert_equal 'victim-org', team.organization
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/team.rb (L10-15)
```ruby
    has_many :github_hooks,
             -> { where(event: REQUIRED_HOOKS) },
             foreign_key: :organization,
             primary_key: :organization,
             class_name: 'GithubHook::Organization',
             inverse_of: false
```
