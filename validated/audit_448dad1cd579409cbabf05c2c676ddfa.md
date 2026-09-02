### Title
Cross-organization team-membership forgery via unscoped `github_id` lookup in `MembershipHandler#find_or_create_team!` combined with login-only identity binding in `User.find_or_create_by_login!` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` resolves the target `Team` solely by `params.team.id` (`github_id`) and the target `User` solely by `params.member.login`, without ever checking that the webhook's *verified signing organization* actually owns that team, or that the login belongs to the same GitHub account as any pre-existing `User` row. Because webhook signature verification is scoped per-organization using an attacker-controllable `organization.login` field, an attacker who legitimately owns any org onboarded to Shipit can sign a `membership` webhook with their own valid secret while naming a different org's real, already-configured privileged team ID and an arbitrary existing user's login, granting that user membership in a team it was never actually added to on GitHub.

### Finding Description
The claimed-safe binding is: `Team.find_or_create_by!(github_id: params.team.id).organization == verified_signing_organization(params.organization.login)`. Tracing the code shows this equality is never enforced.

- `WebhooksController#verify_signature` selects the HMAC secret via `Shipit.github(organization: repository_owner)`, where `repository_owner` falls back to `params.dig('organization', 'login')` for org-scoped events such as `membership` [1](#0-0) . This field is fully attacker-controlled JSON; the attacker only needs to name *an* organization for which they legitimately hold the configured webhook secret (their own onboarded org), and the signature check passes for that org [2](#0-1) .
- `MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)`, matching purely on the numeric GitHub team ID from the payload — with no check that this team's `organization` matches the org that was cryptographically verified in the previous step [3](#0-2) .
- The privileged teams referenced by `authorized?` are pre-created via `Shipit.github_teams`, which resolves real `github_id`s for the operator-configured `organization/slug` pairs at boot time [4](#0-3) . If the attacker supplies `team.id` equal to one of these already-existing `github_id`s, `find_or_create_by!` finds and returns that *exact* pre-existing, privileged `Team` row — the creation block (which would otherwise set `team.organization`) is skipped entirely because the record already exists.
- `team.add_member(member)` appends the resolved `member` to `members` unless already present [5](#0-4) .
- `member` itself is resolved via `User.find_or_create_by_login!(params.member.login)`, which does `find_or_create_by!(login:)` — matching only the login string, never validating/updating `github_id` for a pre-existing row [6](#0-5) .
- `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?`, comparing local Rails primary keys of `Team`, meaning the Membership created above directly satisfies this authorization check for the real privileged team [7](#0-6) .

None of the existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) prevent this, because they only validate payload shape and the signing organization identity — never that the referenced `team.id` belongs to that same signing organization, nor that `member.login` corresponds to the same GitHub account as any pre-existing `Shipit::User` row.

Attacker's exact request: a `POST /webhooks` with `X-Github-Event: membership`, signed with the webhook secret of an org the attacker legitimately controls (`organization.login` = attacker's own org), body containing `action: 'added'`, `team: { id: <real privileged team's github_id>, name, slug, url }`, `member: { login: '<existing user's login, e.g. CI bot>' }`.

### Impact Explanation
A successful request grants an existing `Shipit::User` row (which may correspond to a bot account, CI account, or any previously-seen contributor login) membership in a real, operator-configured privileged `Shipit::Team`, without any actual GitHub-side team change occurring. This directly satisfies `User#authorized?`, which gates access to the entire Shipit application (deploys, rollbacks, stacks) per `force_github_authentication` [8](#0-7) . If that login is later claimed or renamed on GitHub by the attacker (or the attacker already controls a GitHub account with that exact login for some other purpose), they obtain fully authorized session access to Shipit. This matches the "High - escalation into `Shipit.github_teams` authorization" impact category, and is repeatable against any privileged team whose numeric GitHub ID becomes known and any target login already present in the `users` table.

### Likelihood Explanation
Preconditions: (1) the attacker must control at least one GitHub organization/repository that is legitimately onboarded to Shipit with a working webhook secret (feasible for any external repo owner who integrates their own repo with a shared Shipit instance, or any org whose webhook secret has otherwise leaked/been reused); (2) the attacker must know the numeric `github_id` of a privileged team configured in `Shipit.github_teams`; (3) a `User` row with the targeted login must already exist in Shipit's database. None of these require Shipit operator secrets, session cookies, or API tokens. The main friction is discovering the target team's numeric GitHub ID, which is plausible via GitHub's teams API or prior observation, and is explicitly granted as a precondition in this analysis.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the `Team` lookup by both `github_id` AND the verified signing organization (reject/ignore the event if an existing team's `organization` does not match the webhook's authenticated organization). In `User.find_or_create_by_login!`, when a login match is found for a pre-existing row, verify the returned account's `github_id` against a fresh GitHub API lookup before trusting webhook-driven mutations (or track and validate `github_id` on `member`, not just the mutable `login` string), refusing to grant team membership on a login-only collision.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`):
1. Create `shipit_users(:ci_bot)` fixture / `User.create!(login: 'ci-bot', github_id: 999, name: 'CI Bot')` simulating a pre-existing bot user created via an unrelated path.
2. Create a `Team` fixture simulating an already-configured privileged team: `privileged = Team.create!(github_id: 555, organization: 'realorg', slug: 'admins', name: 'Admins', api_url: '...')`; stub `Shipit.github_teams` to return `[privileged]`.
3. Configure a second, attacker-controlled org (`attacker-org`) in `Shipit.github(organization: 'attacker-org')` with a known webhook secret, and compute a valid HMAC signature for that secret over a forged payload: `{ action: 'added', team: { id: 555, name: 'Admins', slug: 'admins', url: '...' }, organization: { login: 'attacker-org' }, member: { login: 'ci-bot' } }`.
4. `POST :create` to the webhooks endpoint with `X-Github-Event: membership` and the computed `X-Hub-Signature` for `attacker-org`'s secret.
5. Assert response is `:ok`, assert `privileged.members.reload.include?(ci_bot)` is `true`, and assert `ci_bot.authorized?` becomes `true` — demonstrating the equality `team.organization == verified_signing_organization` was never checked and cross-org escalation occurred without any real GitHub team-membership event.

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
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
