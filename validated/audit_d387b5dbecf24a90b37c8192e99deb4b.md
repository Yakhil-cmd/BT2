### Title
Forged webhook `repository.owner.login` decouples signature-verification organization from trusted `params.organization.login`, allowing cross-org `Team` row poisoning of `Shipit.github_teams` - ([File: `app/controllers/shipit/webhooks_controller.rb`], [File: `app/models/shipit/webhooks/handlers/membership_handler.rb`])

### Summary
`WebhooksController#verify_signature` picks which organization's `webhook_secret` to check the HMAC against using `repository_owner`, which is read from the attacker-controlled `params.dig('repository','owner','login')` (falling back to `organization.login`) rather than from any authenticated identity. `MembershipHandler#find_or_create_team!` then trusts a *different, independently attacker-controlled* field, `params.organization.login`, plus `params.team.{id,name,slug,url}`, to create a new `Team` row, with no cross-check that the two match.

### Finding Description
The broken binding: **`repository_owner used for signature verification == params.organization.login used to persist the Team row`** should always hold, but nothing enforces it.

- `repository_owner` in [1](#0-0)  reads `params.dig('repository','owner','login') || params.dig('organization','login')` directly out of the raw, attacker-supplied JSON body.
- `verify_signature` uses that value to select which org's `GitHubApp`/`webhook_secret` to validate the HMAC against: [2](#0-1) .
- `MembershipHandler#find_or_create_team!` independently reads `params.team.id/name/slug/url` and `params.organization.login` from the same body to create a `Team` row, with no comparison to `repository_owner`: [3](#0-2) .
- `Team.find_or_create_by_handle`, invoked lazily by `Shipit.github_teams`, matches purely on `organization`+`slug` in the DB, with no verification against GitHub once a row exists: [4](#0-3)  and [5](#0-4) .

Exploit flow: an attacker who legitimately administers a *different* org/repo already onboarded to this Shipit instance (thus knows the `webhook_secret` configured for their own org, e.g. `acme`) POSTs to `/webhooks` with header `X-Github-Event: membership` and a JSON body containing:
```json
{
  "action": "added",
  "repository": {"owner": {"login": "acme"}},
  "organization": {"login": "shopify"},
  "team": {"id": 999999, "name": "Fake", "slug": "developers", "url": "http://x"},
  "member": {"login": "attacker-controlled-user"}
}
```
signed with `acme`'s real `webhook_secret`. `repository_owner` resolves to `acme` (from the forged `repository` key), so `verify_signature` validates against `acme`'s secret — which the attacker legitimately has — and passes. `drop_unhandled_event`/`ExplicitParameters` schema only check presence of `team`/`organization`/`member` fields, not their consistency with `repository_owner`, so nothing blocks this. `MembershipHandler` then creates a new `Team(organization: 'shopify', slug: 'developers', github_id: 999999)` and adds the attacker-chosen `member` to it.

Once this row exists, any later invocation of `Shipit.github_teams` (lazily memoized, called from `User#authorized?`) resolves `'shopify/developers'` via `find_by(organization: 'shopify', slug: 'developers')`, which returns the attacker-seeded row instead of contacting GitHub, because `find_or_create_by_handle` never re-validates an existing DB row against GitHub: [6](#0-5) .

### Impact Explanation
The attacker's forged `member` becomes a member of the `Team` object Shipit treats as the trusted `shopify/developers` team, which is used by `User#authorized?` to gate whether a logged-in GitHub user is authorized to use Shipit at all when `Shipit.github_teams` is non-empty. This is escalation into `Shipit.github_teams` authorization (matching the High severity category). It is repeatable for any handle listed in `Shipit.secrets.github.oauth.teams`, as long as no legitimate row for that `organization`/`slug` pair exists yet (a "first-contact race"), and requires only that the attacker control one legitimately onboarded, unrelated org on the same Shipit instance.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment where distinct organizations have distinct `webhook_secret`s configured in `secrets.github`, and the attacker legitimately controls at least one such org/app (plausible for self-service multi-tenant setups where org admins provision their own GitHub App/webhook secret); (2) the race against the real `shopify` org's own first `membership` webhook for that handle — i.e., this must happen before Shipit has already created the authentic `Team` row for `shopify/developers`. This is a first-contact-only race, not exploitable once the legitimate row exists (since `find_or_create_by_handle` short-circuits to the existing row by `organization`+`slug`, and `MembershipHandler` matches by `github_id`, not `organization`+`slug`, so a second attacker webhook can't overwrite an already-created legitimate row). Given these preconditions, the attack itself is cheap and fully repeatable per handle.

### Recommendation
Bind the two identities together: `WebhooksController` should pass the verified/selected organization (the one whose `webhook_secret` matched) into the handler context, and `MembershipHandler#find_or_create_team!` (and any other handler trusting `organization.login`) should assert `params.organization.login.casecmp(verified_organization) == 0` before creating/updating records, rejecting mismatches. Alternatively, derive `repository_owner` solely from a field whose presence/shape is guaranteed by the specific event schema (e.g., for `membership` events, always use `params.organization.login`, never an attacker-insertable `repository` key that GitHub does not actually send for that event type).

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (illustrative)
test ":membership webhook can seed a Team for an org whose secret is not held by the sender" do
  # 'acme' org is configured with its own webhook_secret in secrets.github, known to the attacker.
  # 'shopify' org has a *different* webhook_secret unknown to the attacker.
  payload = {
    action: 'added',
    repository: { owner: { login: 'acme' } },       # selects acme's webhook_secret for verification
    organization: { login: 'shopify' },              # trusted blindly by MembershipHandler
    team: { id: 999_999, name: 'Fake', slug: 'developers', url: 'http://x' },
    member: { login: 'attacker_user' }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', acme_webhook_secret, payload)}"
  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = signature

  assert_difference -> { Team.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  seeded = Team.find_by(organization: 'shopify', slug: 'developers')
  assert seeded.present?
  assert_equal 999_999, seeded.github_id

  # Now Shipit.github_teams resolves to the attacker-seeded row instead of fetching from GitHub.
  Shipit.stubs(:github).returns(stub(oauth_teams: ['shopify/developers']))
  assert_equal [seeded], Shipit.github_teams
end
```
This demonstrates `repository_owner` (used to select the verifying `webhook_secret`) diverging from `params.organization.login` (used to persist the `Team`), letting an attacker who controls an unrelated, legitimately-onboarded org poison the `Team` row later trusted by `Shipit.github_teams`/`User#authorized?`.

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

**File:** app/models/shipit/team.rb (L18-21)
```ruby
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
