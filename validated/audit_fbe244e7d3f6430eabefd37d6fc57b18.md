## Analysis

I traced the exact call path and the claimed binding does not hold — the vulnerability is real, but the root cause is broader than only `User.find_or_create_by_login!`: it's the combination of that method with `MembershipHandler#find_or_create_team!` matching purely on numeric `github_id`, and `WebhooksController#verify_signature` deriving the authenticating organization from attacker-controlled payload content.

**Binding claimed broken:** `Membership.user_id == a user GitHub reports as a real member of the target Team's organization`. Tracing confirms this equality is never enforced anywhere in the path.

- `WebhooksController#verify_signature` picks the org whose secret to verify against straight from the payload body: `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . Since this same field is also the value later stored as `team.organization`, an attacker who legitimately owns a distinct, low-privilege org (and therefore knows *that org's* `webhook_secret`) can sign a payload whose `organization.login` is their own org, while the `team.id` numeric value targets an already-existing, unrelated, privileged team.
- `MembershipHandler#find_or_create_team!` looks the team up only by `github_id: params.team.id`, and if that Team record already exists (created earlier via a legitimate event for the real org, e.g. Shipit's own `Shipit.github_teams` bootstrap), the `organization` field is not re-validated [2](#0-1) . Nothing ties the org used for signature verification to the org owning the resolved `Team`.
- `User.find_or_create_by_login!` performs a global GitHub existence check (`Shipit.github.api.user(login)`, using the default/global API client) to confirm the login is *some* real GitHub account, but this has no relation to the target team's organization at all [3](#0-2) .
- `MembershipHandler#process` then calls `team.add_member(member)` unconditionally for `action == 'added'` [4](#0-3) , and `Team#add_member` just appends without any org cross-check [5](#0-4) .
- `User#authorized?` grants access purely based on `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) , so once the forged membership is written, the resulting user (real or attacker-chosen login) passes `force_github_authentication` [7](#0-6) .

None of `verify_signature`, `find_or_create_team!`, `find_or_create_by_login!`, or `authorized?` cross-checks that the organization authenticating the webhook actually owns the team being mutated, so the divergence is real.

### Title
Cross-tenant Team hijack via forged membership webhook — org used for signature verification is never bound to the Team being mutated - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a membership webhook using the organization name taken from the same attacker-controlled JSON payload, while `MembershipHandler#find_or_create_team!` resolves an existing `Team` purely by numeric `github_id` with no re-check that it belongs to the authenticating organization. An attacker who legitimately administers any Shipit-configured tenant organization (and thus knows only their own `webhook_secret`) can therefore forge a `membership` `added` event that targets a different, privileged `Team` (one whose `github_id` is in `Shipit.github_teams`) and inject an arbitrary/unverified GitHub login as a member of it.

### Finding Description
Broken binding: `Membership.user_id ↔ team.organization` should equal "a user GitHub confirms as a member of that organization's team", but instead equals "any login string supplied in a payload signed with any org's known secret, matched to a Team purely by numeric `github_id`."

Path:
1. Attacker legitimately controls `attacker-org` in Shipit's multi-tenant GitHub App config and knows its `webhook_secret`.
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: membership`, a valid `X-Hub-Signature` computed with `attacker-org`'s secret, and a JSON body: `{"action":"added","team":{"id":<github_id of an existing privileged Team>,"name":"...","slug":"...","url":"..."},"organization":{"login":"attacker-org"},"member":{"login":"mallory"}}`.
3. `verify_signature` resolves `repository_owner` from the payload's own `organization.login` field [1](#0-0) , fetches `Shipit.github(organization: 'attacker-org')`, and successfully verifies the HMAC since attacker knows that org's secret [8](#0-7) .
4. `MembershipHandler#find_or_create_team!` runs `Team.find_or_create_by!(github_id: params.team.id)`, finds the pre-existing privileged Team by ID (no organization check on the find branch) [2](#0-1) .
5. `User.find_or_create_by_login!('mallory')` creates/looks up a `User` using only a global `Shipit.github.api.user(login)` existence check [3](#0-2) , which proves nothing about org membership.
6. `team.add_member(member)` writes the `Membership` row [5](#0-4) .
7. `mallory.authorized?` now returns `true` via `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) , granting full Shipit access under `force_github_authentication` [7](#0-6) .

None of the listed guards prevent this: `verify_signature` only proves the payload was signed by *some* org's secret, not that the referenced team belongs to that org; `ExplicitParameters` only checks types/presence, not cross-references; `User#authorized?` trusts the `Membership` row unconditionally.

### Impact Explanation
An attacker who is a legitimate low-privilege tenant admin (owns `attacker-org` in Shipit's config) can grant arbitrary GitHub logins membership in any privileged Team already known to Shipit (i.e., any team referenced in `Shipit.github_teams`), bypassing GitHub's actual org/team membership entirely. This is repeatable for any target `Team` record whose `github_id` the attacker can learn (team IDs are frequently discoverable via public GitHub org API endpoints) and grants full authenticated access to the Shipit deploy application — an authorization escalation into `Shipit.github_teams`, matching the High/Critical impact categories (escalation into privileged teams, effectively an authentication bypass since a forged/mis-scoped webhook signature is accepted as authoritative for unrelated content).

### Likelihood Explanation
Requires: (a) a multi-tenant Shipit deployment with more than one configured GitHub App/org and distinct `webhook_secret`s, (b) attacker legitimately controls at least one low-privilege tenant org configured in Shipit, (c) a privileged `Team` record already exists in Shipit's DB (created via normal onboarding of the real org), and (d) attacker can learn/guess that Team's numeric `github_id` (feasible via public GitHub team-listing APIs for many org configurations). Given these commonly-met preconditions, the attack is a single crafted HTTP POST with a self-computed HMAC and is fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, also match/validate on `organization` (not just `github_id`), rejecting or ignoring the event if the resolved `Team#organization` does not equal `params.organization.login` (and by extension the authenticated `repository_owner`). Additionally, pass the already-authenticated organization from the controller into the handler instead of re-reading it from the payload for any authorization-relevant decision, and consider verifying GitHub org/team membership for the `member.login` via that organization's own API client before calling `team.add_member`.

### Proof of Concept
```ruby
test ":membership hijacks a Team from another org's authenticated webhook" do
  target_team = shipit_teams(:shopify_developers) # organization: 'shopify', privileged
  Shipit.stubs(:github_teams).returns([target_team])

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: target_team.github_id, name: target_team.name, slug: target_team.slug, url: target_team.api_url },
    organization: { login: 'attacker-org' }, # attacker's own, legitimately configured org
    member: { login: 'mallory' }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', ATTACKER_ORG_WEBHOOK_SECRET, payload)
  @request.headers['X-Hub-Signature'] = signature

  Shipit.github.api.expects(:user).with('mallory').returns(stub(
    id: 999, name: 'Mallory', login: 'mallory', email: 'mallory@evil.example',
    avatar_url: 'https://avatars.githubusercontent.com/u/999', url: 'https://api.github.com/user/mallory'
  ))

  post :create, body: payload, as: :json
  assert_response :ok

  mallory = User.find_by!(login: 'mallory')
  assert target_team.members.include?(mallory) # binding LHS: Membership.user_id == mallory.id, RHS should require real 'shopify' membership
  assert_predicate mallory, :authorized? # escalation confirmed
end
```
Both sides of the equality — `mallory` was never verified as a member of `shopify` (the org owning `target_team`) — yet `target_team.members.include?(mallory)` and `mallory.authorized?` are both true, confirming the divergence.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
