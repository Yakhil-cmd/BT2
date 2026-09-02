### Title
Membership webhook `organization.login` is not bound to the HMAC-authenticated `repository_owner`, allowing cross-tenant `Team` writes - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification via `repository_owner`, which falls back to `params.dig('repository', 'owner', 'login')` before `params.dig('organization', 'login')`. `MembershipHandler#find_or_create_team!` independently trusts `params.organization.login` to tag/create the `Team` record. Because the attacker controls the entire raw JSON body of the request, they can supply a `repository.owner.login` equal to their own (secret-holding) organization to pass signature verification, while supplying a different `organization.login` (e.g. a victim org) that the handler uses to write the `Team.organization` value.

### Finding Description
The claimed binding is: `organization.login` (used in `MembershipHandler#find_or_create_team!`, [1](#0-0) ) == `repository_owner` (used in `WebhooksController#verify_signature` to select the HMAC secret, [2](#0-1) ).

`repository_owner` is computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) . This is evaluated on the raw request `params`, sourced from the same attacker-supplied JSON body that later feeds `MembershipHandler`. `verify_signature` then does `Shipit.github(organization: repository_owner)` and HMACs the raw body against that organization's configured `webhook_secret` [3](#0-2) , using `GitHubApp#verify_webhook_signature` [4](#0-3) .

Because a real GitHub `membership` event payload has no top-level `repository` key, `repository_owner` in the legitimate case naturally falls back to `organization.login`, keeping the two values equal. However, since the endpoint is reachable by direct unauthenticated HTTP POST, the attacker is not constrained to GitHub's real payload shape — they can add an arbitrary `repository.owner.login` field pointing at their own attacker-controlled organization (for which they legitimately know the `webhook_secret`, since they configured it), while setting `organization.login` to any other org string (e.g., `"victim-org"`).

`MembershipHandler`'s `ExplicitParameters` schema only requires `action`, `team`, `organization.login`, and `member.login` [5](#0-4) ; it does not require or validate `repository`, so the injected `repository.owner.login` field is silently ignored by the handler while still being read by the controller's `verify_signature`. `find_or_create_team!` then does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [1](#0-0) , and `process` calls `team.add_member(member)` for the `added` action [6](#0-5) , with `member.login` being an arbitrary attacker-controlled string resolved via `User.find_or_create_by_login!`.

No code path re-checks that `params.dig('organization','login')` used by the handler equals the `repository_owner` that authenticated the request. `drop_unhandled_event`, the `ExplicitParameters` schema, and model validations on `Team`/`User` do not enforce this cross-check either — they only validate shape, not organizational provenance.

### Impact Explanation
An attacker who legitimately owns/administers `attacker-org` (and thus knows or sets its `webhook_secret` in Shipit's configuration) can forge a `membership` webhook whose HMAC is valid for `attacker-org` but whose `organization.login` field names an arbitrary victim organization. This lets the attacker:
- Create a new `Team` row tagged `organization = "victim-org"` with an attacker-chosen `github_id`/`slug`, or
- If a `Team` for `victim-org` already exists (`github_id` known/guessable or brute-forced), add an arbitrary `member.login` to that team via `team.add_member(member)`.

Since `Shipit.github_teams` authorization decisions key off `Team.organization` and team membership, this is a cross-tenant write that can escalate an attacker (or any user they name) into an authorization role for an organization they do not administer — matching the High severity category "escalation into `Shipit.github_teams` authorization." It is repeatable for any organization name and any `github_id`, and is not scoped to a specific repository, so the blast radius spans all organizations configured in the Shipit instance.

### Likelihood Explanation
Preconditions: the attacker needs only an organization with a `webhook_secret` configured in Shipit for their own org (which the rules state is granted), and the ability to send arbitrary HTTP POSTs to `/webhooks` (also granted, no session/API token/secret needed for the target org). The attacker crafts the JSON body themselves and signs it with their own known secret, so there is no dependency on TLS interception or leaked secrets. This is a single crafted HTTP request, fully repeatable, at low cost.

### Recommendation
In `WebhooksController#verify_signature` and/or `MembershipHandler`, cross-validate the organization used for signature verification against the organization referenced by the handler for record mutation before trusting it — e.g., require `repository_owner` to be derived exclusively from `organization.login` for membership events (or reject payloads where a `repository` key is present but not expected for that event type), and have `MembershipHandler` use the same `repository_owner`/authenticated-org value (not a second independently-parsed `organization.login`) when setting `Team#organization`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub, using the existing `t0kEn`/test webhook_secret fixtures):

```ruby
test "membership event can bind Team to an organization that did not authenticate the signature" do
  attacker_org = 'attacker-org'
  victim_org = 'victim-org'

  # Configure webhook_secret for attacker_org only, matching Shipit.github(organization: attacker_org)
  Shipit.stubs(:github).with(organization: attacker_org).returns(github_app_with_secret('s3cr3t'))

  payload = {
    action: 'added',
    team: { id: 999, name: 'Victim Team', slug: 'victim-team', url: 'https://api.github.com/teams/999' },
    organization: { login: victim_org },
    member: { login: 'attacker' },
    repository: { owner: { login: attacker_org } } # extra, attacker-injected field
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', 's3cr3t', payload)}"

  post shipit.webhooks_path, params: payload,
       headers: { 'X-Github-Event' => 'membership', 'X-Hub-Signature' => signature, 'CONTENT_TYPE' => 'application/json' }

  assert_response :ok # signature verified against attacker_org's secret

  team = Shipit::Team.find_by(github_id: 999)
  # Binding check: organization used for auth (attacker_org) != organization written to the Team (victim_org)
  assert_equal victim_org, team.organization
  refute_equal attacker_org, team.organization
end
```

This demonstrates that the organization authenticating the HMAC (`attacker-org`) and the organization written into `Shipit::Team#organization` (`victim-org`) diverge, confirming the binding claimed in the question is broken.

### Citations

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
