### Title
Cross-organization Team/Membership mutation via `MembershipHandler` team lookup by `github_id` alone - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` resolves the `Team` to mutate solely via `Team.find_or_create_by!(github_id: params.team.id)`, without ever checking that `params.organization.login` (the org whose webhook secret verified the request) matches the `organization` already stored on that `Team` record. Because `WebhooksController#verify_signature` selects the HMAC key using `params.dig('organization','login')` — a field fully controlled by whoever authors the raw POST body — an operator of any org onboarded to Shipit can sign a membership payload with their own org's secret while naming a different org's real `team.id`, causing Shipit to mutate that other org's `Membership` rows.

### Finding Description
The binding that should hold is: `organization that signs the webhook == organization that owns the Team record being mutated`, i.e. `verified_signing_org(params.organization.login) == Team.find_by(github_id: params.team.id).organization`.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')`; a `membership` event has no `repository` key, so `repository_owner` is exactly the attacker-supplied `organization.login` field of the JSON body they are POSTing. [1](#0-0) [2](#0-1) 
- `Shipit.github(organization: repository_owner)` selects the `GitHubApp` config (and thus `webhook_secret`) keyed by that literal org name, and `verify_webhook_signature` HMACs the raw body with it. [3](#0-2) 
Since the attacker controls a real, verified org onboarded to Shipit, they know that org's own `webhook_secret` (it is configured for their own installation) and can therefore produce a valid signature for a body where `organization.login` is set to their own org — passing `verify_signature` — while every other field of the same body, including `team.id`, is attacker-controlled.
- `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)`. The `organization` field is only assigned inside the `create` block (i.e. only used when no team exists yet); for an **existing** team (the common, realistic case — the victim org's team was already created by a prior legitimate webhook) the lookup is purely by `github_id`, with no comparison against `params.organization.login`. [4](#0-3) 
- For `action == 'removed'`, the handler then runs `team.members.delete(member)` on whatever `Team` was returned, deleting the `Membership` row unconditionally. [5](#0-4) 

No other guard closes this gap: `drop_unhandled_event` only checks the event type exists a handler for it, `ExplicitParameters` only validates types/presence of `action`, `team.id/name/slug/url`, `organization.login`, `member.login` — not their consistency with the persisted `Team#organization`, and `User#authorized?` merely checks team membership after the fact, so once the row is deleted the victim is deauthorized. [6](#0-5) 

Attack: attacker (owner/admin of `evil-org`, which is a legitimate Shipit-onboarded org with its own `webhook_secret`) discovers or knows the numeric GitHub team id of a target org's Shipit-authorizing team (`Shipit.github_teams`), builds a `membership` webhook JSON body with `action: 'removed'`, `team.id` = the target's real team id, `organization.login: 'evil-org'`, `member.login` = the victim operator's GitHub login, computes `X-Hub-Signature` using `evil-org`'s own `webhook_secret`, and POSTs it to `/webhooks`. Signature verification succeeds (it only proves the request came from `evil-org`), but the mutation is applied to the target org's pre-existing `Team`/`Membership` records.

### Impact Explanation
This lets a payload signed by one organization mutate another organization's `Team`/`Membership` state — deleting a legitimate operator's `Membership` row for the target team, which is consumed by `User#authorized?` to gate access to `Shipit.github_teams`-protected actions (deploys, rollbacks, etc.). This directly matches the rules' Critical category "a payload for one repository mutating another's stack, commit, task or team," and is repeatable against any org onboarded to Shipit whose team `github_id` is known/guessable, against any member of that team, at will and without any interaction from the victim org.

### Likelihood Explanation
Preconditions are modest: the attacker must control (or register) at least one org that is legitimately onboarded to the Shipit instance (so a `GitHubApp`/`webhook_secret` config exists for it) — the rules explicitly grant "attacker who controls a verified org" as in-scope. They additionally need the numeric `team.id` of the victim's authorizing GitHub team, which is discoverable via the public/authenticated GitHub Teams API or from any prior webhook/log exposure; team ids are sequential/enumerable and not treated as secret. No target secrets, sessions, or tokens are required. The attack is a single crafted HTTP POST, fully repeatable.

### Recommendation
In `MembershipHandler#process` (and `find_or_create_team!`), verify that `params.organization.login` matches the `organization` already stored on any pre-existing `Team` found by `github_id`, and reject/no-op (or raise) the event if they differ, before performing `add_member`/`team.members.delete`. Alternatively, scope the `find_or_create_by!` lookup by both `github_id` and `organization` together, so a team can never be resolved by an org other than the one whose signature verified the request.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/membership_handler_test.rb (conceptual, minitest)
test "'removed' action from another organization's webhook deletes an unrelated org's membership" do
  target_team = shipit_teams(:some_target_team) # organization: "target-org", github_id: 555
  victim = shipit_users(:walrus)
  target_team.add_member(victim)
  assert target_team.members.include?(victim)

  payload = {
    action: 'removed',
    team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
    organization: { login: 'evil-org' }, # attacker's own org, whose secret they know
    member: { login: victim.login }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', evil_org_webhook_secret, payload)

  post '/webhooks',
       params: payload,
       headers: { 'X-Github-Event' => 'membership', 'X-Hub-Signature' => signature, 'CONTENT_TYPE' => 'application/json' }

  assert_response :ok
  # Binding check: organization that signed ('evil-org') != team.organization ('target-org'),
  # yet the membership was still destroyed.
  refute target_team.reload.members.include?(victim)
end
```
This demonstrates the equality `signing_org('evil-org') == team.organization('target-org')` is false, yet the mutation proceeds, confirming the broken webhook-provenance binding.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
