### Title
Membership webhook accepts any org whose GitHub App config has no `webhook_secret`, and `MembershipHandler` binds `Team` purely by `github_id` with no organization check, allowing cross-org authorization bypass - (File: app/models/shipit/webhooks/handlers/membership_handler.rb, app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the signing key by `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the attacker-controlled JSON body (`organization.login`) for membership events. [1](#0-0)  If that named org's `GitHubApp` config has no `webhook_secret`, `verify_webhook_signature` short-circuits to `true` with no signature required at all. [2](#0-1)  `MembershipHandler#find_or_create_team!` then looks up the `Team` solely by `params.team.id` (`github_id`), never checking that the team's true `organization` matches the org that supposedly signed the request, so an attacker can add themselves to any pre-existing `Team` row whose `github_id` they can guess. [3](#0-2) 

### Finding Description
Broken binding: `Team#github_id (existing row in Shipit.github_teams)` == `a github_id whose owning GitHub organization matches the org that authenticated this specific webhook request`. This equality is never enforced.

Code path:
1. `WebhooksController#create` parses `params` and dispatches to `Shipit::Webhooks.for_event(event)` after `before_action :verify_signature`. [4](#0-3) 
2. `verify_signature` computes `repository_owner` as `params.dig('repository','owner','login') || params.dig('organization','login')` — for a `membership` event body, this is `organization.login`, fully attacker-controlled. [5](#0-4) 
3. `Shipit.github(organization: repository_owner)` resolves the `GitHubApp` config for that org via `github_app_config`, raising `GithubOrganizationUnknown` only if the org key is entirely absent from `secrets.github`. [6](#0-5)  If the org is a legitimate installed org whose config simply omits `webhook_secret` (a documented "optional" field, per `docs/setup.md`), `verify_webhook_signature` returns `true` unconditionally, regardless of the `X-Hub-Signature` header's presence/validity. [2](#0-1) 
4. `Webhooks.for_event('membership')` dispatches to `MembershipHandler`. [7](#0-6)  `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` — a global lookup by numeric ID with no scoping to the request's claimed `organization.login`. [3](#0-2) 
5. `User.find_or_create_by_login!(params.member.login)` creates/finds the attacker's `User`, and `team.add_member(member)` inserts a `Membership` row. [8](#0-7) 
6. `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` — since the attacker is now a member of a `Team` whose `github_id` matches an entry in `Shipit.github_teams`, `authorized?` returns true. [9](#0-8) 

Existing guards fail because: `verify_signature` only distinguishes "unknown organization key" from "known organization key," not "org that actually owns this `team.id`." `find_or_create_team!` has no `organization` filter in its lookup (it only sets `organization` on creation, in the `else` block, not as a match condition), so an existing `Team` row created under org A can be mutated/joined via a request that authenticates (or bypasses auth) as org B. There is no cross-check between `params.organization.login` (used to pick the verification key) and the `organization` column of the resolved `Team`.

### Impact Explanation
Any operator running a multi-org Shipit install (using the `Shipit.github_apps`/per-organization config schema) where at least one configured org has no `webhook_secret` set is exposed: an attacker can add arbitrary GitHub logins as members of any `Team` referenced by `Shipit.github_teams`, without any valid webhook signature. Since `User#authorized?` (`app/models/shipit/user.rb:80-82`) gates the entire authorization model of the instance around membership in `Shipit.github_teams`, this is a full authentication/authorization bypass affecting every stack, deploy, rollback, and API action gated by `require_permission!`/`authorized?` for the whole install — matching the "Critical: authentication bypass" and "High: escalation into `Shipit.github_teams` authorization" categories. The attack is repeatable per victim team (each request is independent, keyed only by a guessable/enumerable integer `github_id`) and is not scoped to a single repository — it compromises the operator's authorization boundary globally.

### Likelihood Explanation
Preconditions are non-trivial but realistic: (1) the install must use the multi-org GitHub App config format (`Shipit.github_apps`), (2) at least one configured org must have `webhook_secret` blank — documented as "optional" in `docs/setup.md`, so this is a plausible real-world misconfiguration, and (3) the attacker must know or guess a `github_id` of a `Team` in `Shipit.github_teams` — GitHub team IDs are sequential integers and can be enumerated or learned via public GitHub API team-listing endpoints for orgs the attacker can query, or leaked via prior webhook payloads. No GitHub session, API token, or Shipit credential is needed; the attacker only needs to know the target host's `/webhooks` URL. Given the low cost (single unauthenticated POST) and repeatability, likelihood is credible whenever the misconfiguration precondition holds.

### Recommendation
1. In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization: params.organization.login`, and reject/no-op if an existing `Team` with that `github_id` belongs to a different organization than the one in the payload.
2. In `WebhooksController#verify_signature`, treat a blank/missing `webhook_secret` for a configured org as a hard misconfiguration error (refuse to accept unsigned webhooks) rather than silently trusting all requests claiming that org, or require operators to always set `webhook_secret`.
3. Cross-validate that the `organization.login` used to select the signing key actually owns the `team.id`/`repository` referenced in the payload before mutating any `Team`/`Membership` records.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test ":membership from an org without webhook_secret can hijack an existing team's github_id" do
  # Arrange: configure an org "attacker-org" with no webhook_secret, distinct from the
  # victim team's real organization "shopify".
  Shipit.stubs(:secrets).returns(secrets_with_org_missing_webhook_secret("attacker-org"))

  victim_team = shipit_teams(:shopify_developers) # organization: "shopify", real github_id
  attacker_login = "attacker"

  @request.headers['X-Github-Event'] = 'membership'
  # No X-Hub-Signature header sent at all.
  body = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'attacker-org' }, # attacker-controlled org, no webhook_secret
    member: { login: attacker_login }
  }.to_json

  assert_difference -> { Membership.count }, 1 do
    post :create, body:, as: :json
    assert_response :ok
  end

  attacker_user = User.find_by(login: attacker_login)
  assert Membership.exists?(user: attacker_user, team: victim_team)
  assert attacker_user.teams.exists?(id: victim_team.id)
  # Demonstrates authorization bypass:
  assert attacker_user.authorized? if Shipit.github_teams.map(&:id).include?(victim_team.id)
end
```
This asserts both sides of the claimed broken binding: the `Team` matched (`victim_team`, `organization: "shopify"`) differs from the org used to bypass signature verification (`"attacker-org"`), yet the membership write and resulting `authorized?` escalation still succeed.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
      end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
