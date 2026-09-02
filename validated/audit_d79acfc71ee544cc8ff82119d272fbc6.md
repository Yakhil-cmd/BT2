### Title
Cross-organization team membership escalation via webhook `membership` handler ignoring organization/team binding - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` only proves that the sender controls the GitHub App secret for the organization named in the payload's `organization.login` (or `repository.owner.login`), never that this organization owns the `team.id` referenced in the same payload. `MembershipHandler#find_or_create_team!` looks up/mutates `Shipit::Team` purely by `github_id: params.team.id`, with no check that `params.organization.login` matches the team's stored `organization`. An attacker who controls any org with a Shipit GitHub App installed (even a minimal/staging tenant) can forge a `membership` event that authenticates against their own org's secret while naming a `team.id` belonging to a completely different, already-tracked org, and add an arbitrary GitHub login as a member of that foreign team.

### Finding Description
The broken binding, stated explicitly: **the organization whose `webhook_secret` verified the payload (`repository_owner` == `params.dig('organization','login')` when `repository` key is absent) must equal the organization owning `params.team.id`** — but nothing in the code enforces this equality.

Path:
1. `repository_owner` [1](#0-0)  falls back to `params.dig('organization', 'login')` because `membership` payloads never include a `repository` key.
2. `verify_signature` [2](#0-1)  resolves `Shipit.github(organization: repository_owner)` and validates the HMAC signature against **that org's** configured `webhook_secret`. If the attacker's own org, e.g. `attacker-org`, has any Shipit GitHub App configuration, this succeeds using a secret the attacker legitimately possesses.
3. `MembershipHandler#process` and `#find_or_create_team!` [3](#0-2)  then locates the `Team` solely by `github_id: params.team.id` and calls `team.add_member(member)` / `team.members.delete(member)`. There is no comparison between `params.organization.login` and the resolved team's `organization` attribute — if a team with that `github_id` already exists (e.g. `shipit_teams(:shopify_developers)`, `github_id: 1`), `find_or_create_by!`'s block (which sets `team.organization = params.organization.login`) never runs, so the pre-existing victim team is used unmodified except for the member mutation.
4. `Team#add_member` [4](#0-3)  appends the attacker-supplied `member.login` (resolved to a real `Shipit::User` via `User.find_or_create_by_login!`, which only requires the login to exist on GitHub globally — not in the victim org) to that team's membership.

None of the existing guards prevent this: `verify_signature` validates sender identity for the org named in the payload, not the team's org; the `ExplicitParameters` schema for `MembershipHandler` only validates types/presence of `team.id/name/slug/url`, `organization.login`, `member.login` — no cross-field consistency; `force_github_authentication` and `User#authorized?` are irrelevant here because this path is unauthenticated (webhook) and directly mutates the very `teams` table that `authorized?` later reads.

Attacker request: an HTTP POST to `/webhooks` with header `X-Github-Event: membership`, body `{ "action": "added", "team": { "id": 1, "name": "Developers", "slug": "developers", "url": "..." }, "organization": { "login": "attacker-org" }, "member": { "login": "attacker-github-login" } }`, signed with `attacker-org`'s own legitimately-known `webhook_secret`.

### Impact Explanation
The attacker adds their own (or any) GitHub login as a member of a `Shipit::Team` belonging to a foreign, unrelated organization already tracked by Shipit. If that team is part of `Shipit.github_teams` [5](#0-4) , the resulting membership directly satisfies `User#authorized?` [6](#0-5) , which gates `force_github_authentication` [7](#0-6) . This grants the attacker's Shipit account full authenticated access to the application (viewing/deploying stacks, etc.) without ever belonging to the victim org. This is repeatable against any `github_id` the attacker can guess/enumerate (small sequential integers in this schema) and is not scoped to a single repository — it is a genuine escalation into `Shipit.github_teams` authorization, matching the **High** severity category defined in the rules (not the RCE/secret-exfiltration/forged-session Critical category).

### Likelihood Explanation
Preconditions: the attacker must control an org that Shipit already has *some* GitHub App configuration for (any tenant, including a minimal/staging install is sufficient, since only `webhook_secret` needs to be present and correct for that org). No Shipit session, API token, or victim-org secret is needed. The attacker also needs the `github_id` of the target team, which is a small integer and can plausibly be enumerated/brute-forced (team creation happens sequentially and IDs are not treated as secrets anywhere in the code). Given these conditions, the exploit is a single unauthenticated HTTP POST, fully repeatable.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that `params.organization.login` matches the existing team's `organization` before mutating membership (e.g., look up by `github_id: params.team.id, organization: params.organization.login`, or explicitly reject/raise if a team with that `github_id` exists under a different organization). Additionally, `WebhooksController#verify_signature` should reject `membership` payloads whose `team`/`organization` do not correspond to a `Shipit::Team`/org combination already known to Shipit, rather than trusting `organization.login` alone for signature scoping.

### Proof of Concept
```ruby
test ":membership event with mismatched organization mutates a foreign team" do
  @request.headers['X-Github-Event'] = 'membership'
  victim_team = shipit_teams(:shopify_developers) # organization == 'shopify', github_id == 1

  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    stub(verify_webhook_signature: true)
  )

  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker-login' }
  }.to_json

  assert_difference -> { victim_team.reload.members.count }, 1 do
    post :create, body: payload, as: :json
    assert_response :ok
  end

  # Binding check: organization that verified the signature ('attacker-org')
  # != organization owning the mutated team ('shopify')
  refute_equal 'attacker-org', victim_team.reload.organization
  assert victim_team.members.exists?(login: 'attacker-login')
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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
