### Title
Membership webhooks accepted without signature verification when `webhook_secret` is unset, allowing forged team-membership escalation into `Shipit.github_teams` - (File: `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is not configured for an organization, so `WebhooksController#verify_signature` accepts any unsigned, attacker-crafted `membership` payload for that org. `MembershipHandler#process` then creates a `Membership` row directly from the payload with no independent GitHub check that the named user is actually on that team, letting an attacker forge their own GitHub login into a team configured in `Shipit.github_teams` and become authorized on next OAuth login.

### Finding Description
The binding that should hold: `Membership(team_id: T, user_id: U)` exists in Shipit **iff** GitHub's team-members API actually lists `U` as a member of team `T`. This binding is broken because the only two checks performed are (1) webhook signature verification and (2) that `U`'s login exists on GitHub at all — neither confirms `U ∈ members(T)`.

- `WebhooksController#verify_signature` resolves the app via `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-controlled JSON body (`params.dig('organization', 'login')`) — [1](#0-0) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank: `return true unless webhook_secret` — [2](#0-1) . This is a documented/legitimate configuration state (`webhook_secret: # nil` appears in the sample secrets files) — [3](#0-2) .
- With no signature required, `MembershipHandler#process` trusts `params.team.id`, `params.organization.login`, and `params.member.login` wholesale: it finds/creates the `Team` by `github_id` and, for `action: 'added'`, calls `team.add_member(member)` where `member = User.find_or_create_by_login!(params.member.login)` — [4](#0-3) .
- `Team#add_member` performs no GitHub cross-check, simply appending to the `members` association — [5](#0-4) .
- `User.find_or_create_by_login!` does call `Shipit.github.api.user(login)`, so it validates the login *exists* on GitHub and populates the real `github_id` for that account, but it never checks team membership — [6](#0-5) .
- Critically, `github_id` is the same key used to match users on real OAuth login: `sign_in_github` calls `User.find_or_create_from_github(auth.extra.raw_info)`, which does `find_by(github_id: github_user.id)` — [7](#0-6) [8](#0-7) . This means the forged `User`/`Membership` row created by the webhook is the *same* row an attacker's own legitimate OAuth login resolves to.
- `User#authorized?` only checks the local `teams` association, never re-querying GitHub: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` — [9](#0-8) , enforced at every request via `force_github_authentication` — [10](#0-9) .

**Exploit flow**: attacker picks any org configured in Shipit whose `webhook_secret` is unset and whose team is in `Shipit.github_teams` (team `github_id` must be known/guessed by the attacker, e.g. via the org's public team listing). They POST to `/webhooks` with header `X-Github-Event: membership` and body `{action: 'added', team: {id: <team_github_id>, name, slug, url}, organization: {login: <org>}, member: {login: <attacker's own real GitHub login>}}`. No signature header is required since verification is bypassed. This creates a `Membership` binding the attacker's real account to the target team. The attacker then completes a normal GitHub OAuth login on the Shipit host; `sign_in_github` resolves to the same `User` row (matched by `github_id`), and `authorized?` now returns true, granting access to the authorization-gated application despite never having been added to the real GitHub team.

None of the listed guards prevent this: `verify_signature` is a no-op for unset secrets by design; `drop_unhandled_event` doesn't apply (membership is a handled event); the `ExplicitParameters` schema only validates shape, not GitHub truth; `force_github_authentication`/`User#authorized?` trust the local `Membership` table which is exactly what was poisoned.

### Impact Explanation
A completely unprivileged internet user who knows (a) an org name with unset `webhook_secret` configured in the host's Shipit `github` secrets, and (b) the numeric `github_id` of a team included in `Shipit.github_teams`, can grant themselves (or any other real GitHub account) membership in that authorization-gated team without ever being invited on GitHub. This is a direct escalation into `Shipit.github_teams` authorization — High severity per the stated impact categories — since it lets an attacker pass `force_github_authentication` and access the full Shipit application (stacks, deploys, tasks) as an "authorized" user. It is repeatable against any org/team combination sharing the misconfiguration, and blast radius spans every stack gated behind that team.

### Likelihood Explanation
Requires the specific but realistic and documented precondition that an org in the Shipit `github` secrets config has no `webhook_secret` set (shown as a valid configuration in the repo's own sample secrets files) and that `Shipit.github_teams` is non-empty for that org. Attacker cost is a single unauthenticated POST to `/webhooks` with a crafted JSON body plus knowledge of the target team's GitHub numeric ID (discoverable via GitHub's teams API if the team isn't secret, or via the attacker's own membership in the org). No secrets, tokens, or privileged roles are needed. This is fully repeatable and requires no live GitHub interaction beyond the one `Shipit.github.api.user(login)` existence check inside `find_or_create_by_login!`.

### Recommendation
- Do not allow `webhook_secret` to be unset/blank as a way to bypass signature verification; require the secret to be present for all configured GitHub Apps, or explicitly reject (422) webhooks for organizations without a configured secret instead of treating them as always-valid.
- In `MembershipHandler#process`, before trusting `team.add_member(member)`, verify the membership against the GitHub API (e.g., re-fetch team members or use the installation's API to confirm `member.login` is actually on `team`) rather than trusting the payload at face value.
- Consider re-validating `authorized?` against a live GitHub check (or periodically via `refresh_members!`) rather than relying solely on locally cached `Membership` rows that originate from webhook payloads.

### Proof of Concept
Minitest plan under `test/controllers/webhooks_controller_test.rb` (or a new test file), no live GitHub required (stub `Shipit.github.api.user`):

```ruby
test "forged membership webhook is accepted when webhook_secret is unset and creates unauthorized escalation" do
  # Precondition: org's webhook_secret unset
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # already stubbed globally in setup
  Shipit.github('shopify').instance_variable_set(:@webhook_secret, nil) # or configure fixture org w/ nil secret

  team = shipit_teams(:shopify_developers)
  Shipit.stubs(:github_teams).returns([team])

  attacker_login = 'attacker_real_login'
  Shipit.github.api.expects(:user).with(attacker_login).returns(
    stub(id: 999, login: attacker_login, name: 'Attacker', email: 'a@example.com',
         avatar_url: 'https://x', url: 'https://api.github.com/users/attacker_real_login')
  )

  @request.headers['X-Github-Event'] = 'membership'
  # No X-Hub-Signature header sent at all

  # Left side of the binding (before): no GitHub relationship exists between attacker and team
  assert_not team.members.exists?(login: attacker_login)

  assert_difference -> { Membership.count }, 1 do
    post :create, body: {
      action: 'added',
      team: { id: team.github_id, name: team.name, slug: team.slug, url: team.api_url },
      organization: { login: team.organization },
      member: { login: attacker_login },
      repository: { owner: { login: team.organization } }
    }.to_json, as: :json
    assert_response :ok
  end

  # Right side of the binding (after): forged Membership exists in Shipit
  # despite zero real GitHub team relationship having been verified
  user = User.find_by!(login: attacker_login)
  assert team.members.include?(user)
  assert user.teams.where(id: Shipit.github_teams.map(&:id)).exists? # user.authorized? would now be true
end
```

This demonstrates: the equality "Membership row exists ⇔ GitHub reports the relationship" fails — a `Membership` is created and `authorized?` becomes true purely from an unsigned, attacker-supplied payload.

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

**File:** config/secrets.development.shopify.yml (L1-9)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
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

**File:** app/models/shipit/user.rb (L46-54)
```ruby
    def self.find_or_create_from_github(github_user)
      find_from_github(github_user) || create_from_github(github_user)
    end

    def self.find_from_github(github_user)
      return unless github_user.id

      find_by(github_id: github_user.id)
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
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
