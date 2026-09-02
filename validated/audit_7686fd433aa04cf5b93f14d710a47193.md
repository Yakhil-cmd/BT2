### Title
Cross-organization `Membership` write via unbound `team.id` lookup escalates into `Shipit.github_teams` authorization - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` looks up the target `Team` solely by the GitHub-global `params.team.id` and never checks that the organization which produced a *valid signature* for the current request is the same organization that owns that `Team` record. Because `User#authorized?` grants `Shipit.github_teams` access purely from the `teams` association (`has_many :teams, through: :memberships`), a `Membership` row written for the wrong organization directly and silently escalates authorization.

### Finding Description
The broken binding, stated as an equality that must hold but does not:

`verified_signing_organization(request) == team.organization` for every `team.add_member(member)` call.

Trace:
- `WebhooksController#verify_signature` resolves the signing organization via `repository_owner`, which reads `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) .
- Once the signature check passes for *some* organization, the raw parsed JSON is handed unmodified to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) .
- `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` — the `organization =` assignment only fires on **create**; for an **existing** `Team` (the common victim case, since the target team was already legitimately created by its real org's earlier webhooks) this branch never runs, and no comparison is ever made between `params.organization.login`/the verified signing org and the found `team.organization` [3](#0-2) .
- `team.add_member(member)` (`app/models/shipit/team.rb:41-43`) then unconditionally appends the attacker-named `member` (created via `User.find_or_create_by_login!(params.member.login)`) to that `Team`'s `members`, i.e. writes a `Membership` row, with no re-check of provenance.
- `User#teams` is `has_many :teams, through: :memberships` [4](#0-3) , so this `Membership` row immediately makes `user.teams.include?(team)` true.
- `User#authorized?` is exactly `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [5](#0-4) , and `Shipit.github_teams` resolves configured team *handles* to `Team` records via `Team.find_or_create_by_handle` [6](#0-5) .

Exploit flow: attacker legitimately controls (with its own real webhook secret) some organization `attacker-org` registered in a multi-org Shipit deployment (`lib/shipit.rb:170-200`, `docs/setup.md:182-209`). They send `POST /webhooks` with `X-Github-Event: membership`, a signature valid for `attacker-org`, and a JSON body whose `organization.login`/`member.login` are attacker-controlled and whose `team.id` equals the real GitHub numeric ID of the victim's oauth-restricted team (e.g. `shopify/developers`, already present in Shipit's DB from that org's own prior legitimate webhooks). `WebhooksController#verify_signature` only validates that *a* signature is valid for `attacker-org`; nothing downstream checks that `attacker-org` is the org that owns `params.team.id`. `MembershipHandler` finds the existing victim `Team` by `github_id` and adds the attacker's user as a member.

Existing guards fail here because: `verify_signature` verifies *authenticity of the sender*, not *authorization of the sender to speak for the named team's organization*; `ExplicitParameters` (`params do ... end`) only enforces types/presence, not cross-field consistency between the verified org and `params.organization.login`/`params.team`; and `Team.find_or_create_by!` keys purely on GitHub's team id, an org-agnostic identifier.

### Impact Explanation
The attacker's own `Shipit::User` gains a `Membership` in a `Team` belonging to an organization they never legitimately joined. If that team's handle is listed in `Shipit.github_teams` (`oauth.teams` config), `User#authorized?` (`app/models/shipit/user.rb:80-82`) flips to `true`, granting the attacker full authenticated access to the Shipit application — stacks, deploy triggers, task streams — gated behind that org's team membership. This is repeatable against any `Team` record whose numeric GitHub `id` the attacker can learn, and scales to any tenant/organization sharing the same multi-org Shipit instance, matching the "High - escalation into `Shipit.github_teams` authorization" category.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (`secrets.github` keyed by org, per `docs/setup.md:182-209`) where the attacker administers at least one registered organization and thus legitimately possesses that organization's own `webhook_secret`; (2) knowledge of the numeric GitHub `team.id` of the victim's oauth-restricted team, which is discoverable via GitHub's own team APIs/UI in many configurations. Given those, the attacker cost is a single crafted, self-signed HTTP POST; no Shipit session, API token, or victim secret is needed. This is fully repeatable and scriptable.

### Recommendation
In `MembershipHandler#find_or_create_team!`/`#process`, verify that the organization which produced the valid webhook signature (as resolved by `WebhooksController#repository_owner`) matches both `params.organization.login` and the existing `team.organization` before calling `team.add_member`/`team.members.delete`; reject (or drop) the event otherwise. Consider passing the verified organization explicitly into the handler rather than trusting `params.organization.login`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/membership_handler_test.rb` (or an addition to `test/controllers/webhooks_controller_test.rb`):
```ruby
test "membership webhook signed for org A cannot add members to org B's team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify'
  attacker_login = 'attacker'

  # Signature is verified against a DIFFERENT org ("attacker-org"),
  # never against 'shopify' -- no legitimate GitHub call to shopify is stubbed.
  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  Shipit.github.api.expects(:user).with(attacker_login).returns(stub(
    id: 999, login: attacker_login, name: 'Attacker', email: 'a@a.com',
    avatar_url: 'https://x', url: 'https://api.github.com/user/attacker'
  ))

  request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: attacker_login },
    repository: { owner: { login: 'attacker-org' } }
  }.to_json

  post :create, body: payload, as: :json
  assert_response :ok

  attacker = User.find_by!(login: attacker_login)
  assert attacker.teams.include?(victim_team), "attacker should NOT be a legit member, but binding is broken"

  Shipit.stubs(:github_teams).returns([victim_team])
  assert attacker.authorized?, "attacker gains Shipit.github_teams authorization without ever contacting shopify"
end
```
Both sides of the binding (`verified_signing_organization == team.organization`) diverge (`attacker-org` vs `shopify`) yet `add_member` still executes and `authorized?` still returns `true`, demonstrating the vulnerability.

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

**File:** app/models/shipit/user.rb (L9-10)
```ruby
    has_many :memberships
    has_many :teams, through: :memberships
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
