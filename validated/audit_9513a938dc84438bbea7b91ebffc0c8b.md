### Title
Cross-tenant `Team` membership mutation via unscoped `github_id` lookup in `MembershipHandler` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a `membership` webhook against the organization taken from `params.dig('organization', 'login')` (there is no `repository` key for this event), and `GithubApp#verify_webhook_signature` returns `true` unconditionally when that organization has no `webhook_secret` configured. `MembershipHandler#find_or_create_team!` then looks up the `Team` to mutate purely by the GitHub-global `team.id`, with no check that the found team's stored `organization` matches the verified `organization.login`. An attacker who can get a request accepted for a secret-less organization can therefore add or remove members on a `Team` record that actually belongs to a completely different, secret-protected organization.

### Finding Description
The binding the question claims should hold is: `verified_org (params.dig('organization','login'), checked in Shipit::WebhooksController#verify_signature)` == `org owning the Team object mutated (team.organization, in Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!)`.

Trace:
- `Shipit::WebhooksController#create` parses `params` and dispatches to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) .
- `repository_owner` falls back to `params.dig('organization', 'login')` when there is no `repository` key, which is exactly the shape of a real GitHub `membership` payload [2](#0-1) .
- `verify_signature` resolves `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature` [3](#0-2) .
- `GithubApp#verify_webhook_signature` returns `true` unconditionally whenever `webhook_secret` is blank for that organization's config: `return true unless webhook_secret` [4](#0-3) .
- `MembershipHandler#process` calls `find_or_create_team!`, which resolves the target `Team` strictly by the attacker-supplied `params.team.id`: `Team.find_or_create_by!(github_id: params.team.id) do |team| ... team.organization = params.organization.login end` [5](#0-4) . The block that assigns `organization` only executes on **create**; if a `Team` row with that `github_id` already exists (e.g., a legitimate team belonging to another, secret-protected organization), the existing record is returned untouched and mutated via `team.add_member(member)` / `team.members.delete(member)` [6](#0-5) .

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: membership`, a JSON body containing `organization: { login: "<secret-less-org>" }`, `team: { id: <victim_team_github_id>, name, slug, url }`, and `member: { login: "<attacker-controlled-or-victim-user>" }`, and no `repository` key. `verify_signature` resolves the org from `organization.login` (the secret-less org) and passes unconditionally because that org has no `webhook_secret`. `MembershipHandler` then finds the pre-existing `Team` with the given `github_id` — which was created for and belongs to a different, secret-protected organization — and adds/removes the specified member, all without ever validating that `organization.login` matches that team's `organization` column.

Existing guards fail because: `drop_unhandled_event` and `ExplicitParameters` schema only check payload shape, not org ownership of the target record; `verify_signature` verifies the signature for the *attacker-chosen* organization, not the organization that actually owns the `Team` being mutated; and there is no per-record tenant check inside `MembershipHandler`.

### Impact Explanation
A successful request adds or removes a `User` from an arbitrary pre-existing `Team` record, regardless of which organization that team belongs to, as long as the attacker can pass signature verification for *some* organization (a secret-less one) and knows/guesses the target team's numeric GitHub `id`. If that `Team`'s handle is listed in `Shipit.github_teams` (used for admin authorization), this becomes escalation into Shipit's privileged authorization group — a High/Critical impact matching "escalation into `Shipit.github_teams` authorization" and "cross-tenant... team mutation." The action is repeatable against any team whose GitHub `id` the attacker can determine, and the blast radius spans every organization configured in the same Shipit instance.

### Likelihood Explanation
Exploitation requires: (1) at least one organization configured in Shipit with no `webhook_secret` set (so `verify_webhook_signature` short-circuits to `true`), and (2) knowledge of the numeric GitHub `team.id` for the target team in a different organization (team IDs are visible via GitHub's public API/UI in many cases). No Shipit session, API token, or any secret is required from the attacker; the request is a single unauthenticated `POST /webhooks`. Likelihood is conditional on the secret-less-org precondition, which is a plausible but not universal Shipit deployment configuration.

### Recommendation
In `MembershipHandler#find_or_create_team!`, do not rely on a global `github_id` lookup alone: scope the lookup by both `github_id` and `organization` (`Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and raise/abort if an existing team with that `github_id` has a different `organization` than the one just verified. Additionally, consider requiring `webhook_secret` to be present for all configured organizations (fail closed) rather than allowing `verify_webhook_signature` to return `true` when unset.

### Proof of Concept
Minitest plan (extends `test/controllers/webhooks_controller_test.rb`):
```ruby
test ":membership cannot mutate a team belonging to a different organization" do
  # Arrange: an existing Team that belongs to "victim-org" (has webhook_secret configured)
  victim_team = Team.create!(github_id: 999, organization: "victim-org", name: "Victims", slug: "victims", api_url: "https://example.com")
  assert_equal "victim-org", victim_team.organization

  # "attacker-org" has no webhook_secret configured -> verify_webhook_signature returns true unconditionally
  Shipit.stubs(:github).with(organization: "attacker-org").returns(stub(verify_webhook_signature: true))

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: 999, name: 'Victims', slug: 'victims', url: 'https://example.com' },
    organization: { login: 'attacker-org' }, # verified org
    member: { login: 'attacker-controlled-user' }
  }.to_json

  assert_no_difference -> { Team.count } do
    post :create, body: payload, as: :json
  end

  victim_team.reload
  # Assert both sides of the binding: verified org ("attacker-org") must equal the org owning the mutated Team ("victim-org")
  refute_equal "attacker-org", victim_team.organization
  # Yet the membership mutation should NOT have occurred, since verified org != team.organization
  refute victim_team.members.exists?(login: 'attacker-controlled-user')
end
```
This test currently fails (the membership mutation succeeds) because `MembershipHandler` never compares `params.organization.login` to the existing `Team#organization`, demonstrating the cross-tenant mutation.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
