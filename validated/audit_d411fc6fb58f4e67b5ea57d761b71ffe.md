### Title
Membership webhook processing trusts `organization.login`/`team.id` from the payload without confirming the org that passed `verify_signature` is entitled to send `membership` events for that org/team — cross-tenant team/membership forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` derives the GitHub App used to check the HMAC solely from `repository.owner.login` (falling back to `organization.login`), while `MembershipHandler#process` independently trusts `params.organization.login` and `params.team.id`/`params.member.login` to create/mutate `Team` and `Membership` records. Because the two lookups read different, attacker-controlled JSON keys, a caller who owns *any* Shipit-configured GitHub App (and therefore knows that app's `webhook_secret`) can sign a payload as their own org while naming a completely different org's team, letting them add themselves (or anyone) to that team's `Membership` records.

### Finding Description
The claimed binding — "the org whose signature verified == the org whose membership event is processed" — is broken.

`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 
and uses it to pick the `GitHubApp` (and thus the `webhook_secret`) for HMAC verification:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
``` [2](#0-1) 

`create` then dispatches purely on the `X-Github-Event` header, passing the raw parsed JSON to the handler with no binding back to the verifying org:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
``` [3](#0-2) 

`MembershipHandler` then reads `params.organization.login` and `params.team.id` unconditionally to find-or-create a `Team` and mutate its `Membership`:
```ruby
def process
  team = find_or_create_team!
  member = User.find_or_create_by_login!(params.member.login)
  case params.action
  when 'added' then team.add_member(member)
  when 'removed' then team.members.delete(member)
  ...
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [4](#0-3) 

Because `repository_owner` (used for signature verification) is read from a top-level `repository.owner.login` key that is independent of `organization.login` (used by the handler), an attacker can supply both keys in one JSON body: `repository.owner.login = "attacker-org"` (their own trusted, Shipit-configured org, whose `webhook_secret` they know because they created/own that GitHub App) and `organization.login = "victim-org"` with `team.id` set to the real `github_id` of an existing, privileged `Team` row (e.g., one referenced by `Shipit.github_teams`). `verify_signature` validates successfully against the attacker's own secret; `check_if_ping`/`drop_unhandled_event` do not inspect `organization` vs `repository`; nothing checks that "attacker-org" is entitled to emit `membership` events for "victim-org" — the legacy `Shipit::GithubHook::Organization` model that once modeled this entitlement is explicitly dead/unused in this path (marked `# TODO: app-migration, delete class`) and is never consulted by `verify_signature` or `MembershipHandler`. [5](#0-4) 

If `params.team.id` matches an existing `Team` whose `id` is included in `Shipit.github_teams`, `User#authorized?` will now consider the attacker's injected member authorized:
```ruby
def authorized?
  @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
end
``` [6](#0-5) 
and access is gated only by this membership check in `force_github_authentication`: [7](#0-6) 

### Impact Explanation
An attacker who controls (or has legitimately configured) any single Shipit-recognized GitHub App/org can forge `membership` events that create or mutate `Team`/`Membership` rows belonging to a completely unrelated org, without ever having real GitHub team membership there. The most severe consequence is escalation into `Shipit.github_teams` authorization: by naming an existing privileged team's `github_id` and adding a controlled login as `member`, the attacker's own `User` record gains `authorized?` = true, granting full access to the Shipit UI/actions gated by team membership — this matches the "escalation into `Shipit.github_teams` authorization" High-severity category. It is fully repeatable per request and not limited to one org pair; any org configured in `secrets.github` can target any other org's teams this way.

### Likelihood Explanation
Preconditions: multi-tenant Shipit deployment with more than one org configured under `secrets.github` (as illustrated in `config/secrets.development.shopify.yml`), and the attacker controls/administers at least one such org (so they know that org's `webhook_secret`, since GitHub App creators set their own webhook secret per `docs/setup.md`). No Shipit session, API token, or victim secrets are needed — only a valid HMAC computed from the attacker's own known secret over a self-crafted JSON body containing a decoupled `repository.owner.login`/`organization.login`. This is a single unauthenticated HTTP POST to `/webhooks`, trivially repeatable.

### Recommendation
Bind membership processing to the verified identity: require `params.organization.login` (and/or `repository.owner.login`) used by the handler to equal the `repository_owner` value that was used for signature verification, and reject the request otherwise. Additionally, reintroduce (or replace with a modern equivalent) an explicit per-org entitlement check — verifying the org that signed the request is actually authorized to emit `membership` events for the named organization/team — before `MembershipHandler#process` is allowed to create/mutate `Team`/`Membership` records.

### Proof of Concept
```ruby
test "membership event forged with a foreign organization/team is rejected" do
  # attacker-org is configured in secrets.github with its own known webhook_secret,
  # but has no entitlement to send 'membership' events for victim-org's team.
  attacker_secret = Shipit.github(organization: 'attacker-org').send(:webhook_secret)
  victim_team = shipit_teams(:shopify_developers) # id referenced by Shipit.github_teams

  body = {
    action: 'added',
    team: { id: victim_team.github_id, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url },
    organization: { login: 'shopify' },        # victim org's login, used by MembershipHandler
    member: { login: 'attacker_login' },
    repository: { owner: { login: 'attacker-org' } } # used only for signature lookup
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', attacker_secret, body)}"
  @request.headers['X-Github-Event'] = 'membership'
  @request.headers['X-Hub-Signature'] = signature

  assert_no_difference -> { victim_team.members.count } do
    post :create, body:, as: :json
  end
  # current (vulnerable) code: response is :ok and victim_team gains 'attacker_login' as a member
  # expected (fixed) behavior: request should be rejected (e.g. 422) because attacker-org
  # is not entitled to send membership events for 'shopify'/victim_team
end
```

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

**File:** app/models/shipit/github_hook.rb (L3-6)
```ruby
module Shipit
  class GithubHook < Record
    # TODO: app-migration, delete class
    belongs_to :stack, required: false # Required for fixtures
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
