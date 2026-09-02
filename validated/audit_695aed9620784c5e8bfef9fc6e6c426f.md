### Title
Membership webhook removal accepted without signature verification when org's `webhook_secret` is unset, allowing unauthorized deauthorization of a Shipit operator - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` delegates to `GitHubApp#verify_webhook_signature`, which returns `true` unconditionally when no `webhook_secret` is configured for the organization. Combined with `MembershipHandler#process`, this lets anyone who can reach `POST /webhooks` with a forged `membership` `removed` event delete a real `Membership` row for an org whose `webhook_secret` is nil, without GitHub ever sending that event.

### Finding Description
The broken binding: `Membership.exists?(user: operator, team: team) == GitHub actually reported a 'removed' membership event for that user/team`. This should always hold, but does not when `webhook_secret` is nil for the org.

Code path:
- `WebhooksController#verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` from the attacker-controlled `organization.login`/`repository.owner.login` fields in the JSON body [1](#0-0) , then calls `github_app.verify_webhook_signature(...)`.
- `GitHubApp#verify_webhook_signature` short-circuits: `return true unless webhook_secret` [2](#0-1) . If that organization's config entry has no `webhook_secret` set (`@webhook_secret = @config[:webhook_secret].presence`, line 50), any payload — signed or not — passes verification.
- `MembershipHandler#process` then executes `team.members.delete(member)` for `action == 'removed'` with no further authorization check, using `params.team.id` and `params.member.login` taken directly from the forged payload [3](#0-2) . `User.find_or_create_by_login!` resolves/creates the member by login, and `find_or_create_team!` resolves the team by `github_id` supplied in the payload [4](#0-3) .
- Deleting the `Membership` row directly affects `User#authorized?`, which is computed as `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [5](#0-4) . Removing the operator's only qualifying membership flips this to `false`.

Why guards fail: `verify_signature`'s only protection is HMAC comparison, and it is deliberately bypassed (returns `true`) whenever the org has no configured secret — this is an operational/config gap, not a code bug in the strict sense, but it is exercised entirely through this engine's own webhook-processing code (`WebhooksController`, `GitHubApp`, `MembershipHandler`) with no other authentication layer. `drop_unhandled_event` only checks that a handler exists for the event type, not payload authenticity. There is no check that the acting `team.organization`/`github_id` combination or the requester's identity corresponds to a real GitHub webhook delivery beyond the (bypassable) signature check.

### Impact Explanation
An attacker who can send an unauthenticated `POST /webhooks` request with `X-Github-Event: membership` and a JSON body naming an existing `Shipit.github_teams` team ID and a legitimate operator's GitHub login can delete that operator's `Membership` record, causing `User#authorized?` to become `false` for that operator — an unauthorized escalation/de-escalation into the `Shipit.github_teams` authorization boundary. This matches the "High" severity category (escalation into `Shipit.github_teams` authorization). The effect is scoped to organizations whose `webhook_secret` is not configured, and is repeatable against any operator/team combination for that organization as long as team `github_id` and the member's `login` are known (both are typically public/discoverable via GitHub).

### Likelihood Explanation
This requires the specific configuration precondition that the targeted organization's `webhook_secret` is unset/nil in Shipit's GitHub app config — this is not the default expectation of a properly configured production deployment, but nothing in the code enforces or validates that `webhook_secret` be present at startup, and `verify_webhook_signature`'s "unless webhook_secret" fallback silently downgrades to no verification rather than failing closed. Given that precondition, attacker cost is trivial: no secrets, no session, a single unauthenticated HTTP POST with guessable/public team ID and login. Repeatable at will.

### Recommendation
Fail closed instead of open in `GitHubApp#verify_webhook_signature`: reject (return `false`) when `webhook_secret` is blank rather than treating a missing secret as "trust the request." Additionally/alternatively, require `webhook_secret` to be present as part of GitHub app configuration validation (e.g., in `Shipit.github`/config loading) so misconfigured organizations cannot silently accept unsigned webhooks. Consider also requiring an explicit deny for `membership`/`removed` events when the deletion would drop a user below the `Shipit.github_teams` authorization threshold without corroborating evidence.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "forged membership 'removed' webhook de-authorizes an operator when org webhook_secret is nil" do
  # Precondition: configure an org whose GitHubApp has webhook_secret == nil
  team = shipit_teams(:shipit) # a team present in Shipit.github_teams
  operator = shipit_users(:walrus)
  Membership.create!(team: team, user: operator)
  assert operator.authorized?  # binding LHS: Membership exists == real GitHub state

  before_count = Membership.count

  post :create, body: {
    action: 'removed',
    team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
    organization: { login: team.organization },
    member: { login: operator.login }
  }.to_json, headers: { 'X-Github-Event' => 'membership' } # no X-Hub-Signature sent

  assert_equal before_count - 1, Membership.count
  assert_not operator.reload.authorized? # LHS flipped without any real GitHub signal (RHS never occurred)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
