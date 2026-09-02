### Title
Membership webhook trusts organization-scoped signature but writes Team membership keyed only by attacker-supplied `team.id`, letting one onboarded organization inject users into another organization's authorization team - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
Shipit supports multi-tenant GitHub App configuration: `Shipit.github(organization:)` resolves a per-organization config (and `webhook_secret`) via `github_app_config` [1](#0-0) . `WebhooksController#verify_signature` picks which organization's `webhook_secret` to validate the HMAC signature against using only `repository_owner` — i.e. `params.dig('repository','owner','login') || params.dig('organization','login')` — taken straight from the untrusted JSON body [2](#0-1) . Once the signature is valid for *that* organization, the entire payload is handed to `Shipit::Webhooks::Handlers::MembershipHandler`, which finds/creates a `Team` purely by `params.team.id` (an attacker-supplied integer) and, on match, calls `team.add_member(member)` without ever checking that `params.organization.login` (the value that was actually authenticated) matches the `organization` already stored on that `Team` record [3](#0-2) .

### Finding Description
The binding that should hold is:
`organization authenticated by webhook signature == organization whose Team membership is mutated`

Before the attacker's payload: a `Team` record for organization "shopify" already exists, created previously via a legitimate `membership` webhook, with `organization: "shopify"` and `github_id: 48` [4](#0-3) . This `Team` may be one of `Shipit.github_teams`, which is the authorization gate used by `User#authorized?`: `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [5](#0-4) .

Shipit is multi-tenant: any organization that has its own GitHub App configured under `secrets.github` (with its own `webhook_secret`) is a legitimate, independently-authenticated tenant of the same Shipit instance [1](#0-0) . An attacker who controls a second, unrelated organization ("attacker-org") onboarded to the same Shipit instance can send a webhook with `X-Github-Event: membership` and a body where `organization.login = "attacker-org"` (so it authenticates correctly against attacker-org's own `webhook_secret`) but `team.id = 48` (the github_id belonging to shopify's team) and `member.login = <victim-or-attacker-controlled-login>`.

After the attacker's request:
- `WebhooksController#verify_signature` succeeds, because it is checking the signature against attacker-org's own legitimately-known `webhook_secret` — no privileged secret is required [6](#0-5) .
- `MembershipHandler#find_or_create_team!` calls `Team.find_or_create_by!(github_id: params.team.id)`. Since a Team with `github_id: 48` already exists (shopify's team), the block that sets `team.organization = params.organization.login` is **not** executed, and `find_or_create_by!` returns the **existing shopify Team object**, matched only by `github_id` [4](#0-3) .
- `team.add_member(member)` is then called on that existing shopify `Team`, adding an arbitrary GitHub login as a member [7](#0-6) , [8](#0-7) .

Nowhere in this code path is `params.organization.login` (the authenticated tenant) compared against the resolved `team.organization` before performing the membership write. The lookup key (`github_id`) and the authentication key (`organization`) are decoupled, breaking the intended equality between "organization whose signature was verified" and "organization/team actually mutated."

### Impact Explanation
If the target `Team` is one of `Shipit.github_teams`, this becomes a direct escalation into `Shipit.github_teams` authorization: an attacker who legitimately controls any onboarded organization can grant an arbitrary GitHub-identified user (which becomes a Shipit `User` via `User.find_or_create_by_login!`) membership in a privileged team, bypassing real GitHub team membership entirely and satisfying `User#authorized?` [5](#0-4) . This matches the in-scope "High" impact category (escalation into `Shipit.github_teams` authorization).

### Likelihood Explanation
This requires no privileged secret, no compromise of the target organization's webhook secret, and no GitHub App private key — only that the attacker controls a second organization that is a legitimate Shipit tenant (a normal, supported multi-tenant configuration per `github_app_config`/`github_organizations`) [9](#0-8) . The only additional requirement is knowledge (or brute-forceable guessing, since GitHub team IDs are small sequential integers) of the victim `Team`'s GitHub `github_id`, which is not treated as secret elsewhere in the codebase (it's a plain integer stored in the `github_hooks`/`teams` tables) [10](#0-9) .

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and the authenticated `organization` (derived from the verified webhook context, not solely `params.organization.login`), and refuse to mutate a `Team` whose stored `organization` does not match the organization that was cryptographically verified by `WebhooksController#verify_signature`. Additionally, `WebhooksController` should pass the verified `repository_owner`/organization through to handlers explicitly, rather than relying on handlers to re-derive it from the same untrusted payload used for the write.

### Proof of Concept
1. Attacker controls "attacker-org", a legitimate second GitHub organization already configured in Shipit's `secrets.github` (its own `webhook_secret`).
2. Attacker discovers (or guesses) the `github_id` of the `Team` record backing one of `Shipit.github_teams` for organization "shopify" (e.g. `48`, as used in the existing test fixture) [11](#0-10) .
3. Attacker sends `POST /webhooks` with `X-Github-Event: membership`, correctly HMAC-signed using attacker-org's own `webhook_secret`, and body:
```json
{
  "action": "added",
  "team": {"id": 48, "name": "x", "slug": "x", "url": "https://example.com"},
  "organization": {"login": "attacker-org"},
  "member": {"login": "victim-or-attacker-login"},
  "repository": {"owner": {"login": "attacker-org"}}
}
```
4. `verify_signature` succeeds against attacker-org's own secret. `MembershipHandler#process` calls `Team.find_or_create_by!(github_id: 48)`, matching shopify's existing team, and calls `team.add_member(User.find_or_create_by_login!("victim-or-attacker-login"))` [12](#0-11) .
5. The specified user is now a member of shopify's privileged team and passes `User#authorized?` [5](#0-4) , gaining access to privileged Shipit functionality gated on `Shipit.github_teams` membership, without ever having real GitHub team membership in shopify's organization.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** test/dummy/db/schema.rb (L134-146)
```ruby
  create_table "github_hooks", force: :cascade do |t|
    t.string "api_url", limit: 255
    t.datetime "created_at"
    t.string "event", limit: 50, null: false
    t.bigint "github_id"
    t.string "organization", limit: 39
    t.string "secret", limit: 255
    t.integer "stack_id", limit: 4
    t.string "type", limit: 255
    t.datetime "updated_at"
    t.index ["organization", "event"], name: "index_github_hooks_on_organization_and_event", unique: true
    t.index ["stack_id", "event"], name: "index_github_hooks_on_stack_id_and_event", unique: true
  end
```

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end
```
