Confirmed: no additional check binds `params.organization.login` (or `repository_owner`) to the team being mutated in `MembershipHandler`, and the `Team.github_id` column has no cross-organization uniqueness constraint enforcing it belongs to the authenticating org. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

### Title
Cross-organization membership webhook forgery lets an attacker who owns one configured GitHub org escalate into another org's `Team`, gaining `Shipit.github_teams` authorization - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#find_or_create_team!` looks up an existing `Team` solely by `github_id`, without checking that `params.organization.login` matches the organization that owns that team record. In a multi-org Shipit deployment, an attacker who legitimately controls one configured GitHub App/org can forge a `membership` webhook payload (self-signed with their own known `webhook_secret`) whose `team.id` collides with the `github_id` of an existing, privileged victim-org `Team`, causing the attacker's own GitHub login to be added as a member of that team and pass `Shipit::User#authorized?`.

### Finding Description
The broken binding: the organization whose `webhook_secret` verified the request must equal the organization owning the `Team` row that gets mutated — i.e. `repository_owner (== params.organization.login for membership events) == team.organization`. This is never checked.

`WebhooksController#verify_signature` derives `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [2](#0-1) , then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)` [6](#0-5) . `GitHubApp#verify_webhook_signature` simply HMACs the raw request body with that org's configured `webhook_secret` and compares it to the supplied signature [7](#0-6) . This check only proves "this exact byte sequence was signed with attacker-org's secret" — it says nothing about the *content* of that byte sequence, which is entirely attacker-controlled once they know their own org's secret (a secret they legitimately possess as the operator of their own GitHub App entry in `Shipit.github_organizations`).

`MembershipHandler#process` then calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [8](#0-7) . The `organization=` assignment inside the block only runs on *creation*; if a `Team` row with that `github_id` already exists (e.g. previously created for `victim-org/admins` and listed in `Shipit.github_teams`), `find_or_create_by!` finds and returns it unmodified, regardless of which organization actually owns it. The database schema confirms `github_id` has no unique or scoping constraint tying it to `organization` — only `(organization, slug)` is uniquely indexed [5](#0-4) . `process` then unconditionally does `team.add_member(member)` for `action == 'added'` [9](#0-8) , adding the attacker's forged `member.login` as a member of the victim's team.

Exploit flow: attacker crafts a JSON body `{"action":"added","team":{"id":<victim_team.github_id>,"name":"x","slug":"x","url":"https://example.com"},"organization":{"login":"attacker-org"},"member":{"login":"attacker-login"}}`, computes `sha1=` HMAC over that exact body using their own org's `webhook_secret`, and POSTs it to `/webhooks` with `X-Github-Event: membership`. `verify_signature` uses `repository_owner = "attacker-org"` (from `organization.login`, since there is no `repository` key in a membership payload), resolves `Shipit.github(organization: 'attacker-org')`, and the signature verifies successfully because it was legitimately computed with that org's own secret. `find_or_create_team!` then finds the *existing* victim `Team` by numeric `github_id` and adds the attacker as a member.

Existing guards do not stop this: `drop_unhandled_event` only checks the event has a registered handler; the `ExplicitParameters` schema only validates types/presence, not cross-field consistency; `force_github_authentication`/`require_permission!` are irrelevant since this is an unauthenticated webhook endpoint by design. `User#authorized?` trusts team membership: `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [4](#0-3) , so once the `Membership` row exists, the attacker's user becomes `authorized?` and gains full application access.

### Impact Explanation
The attacker gains full authenticated access to the Shipit application (deploys, rollbacks, stack management, etc.) without ever being a legitimate member of any team in `Shipit.github_teams`, and without touching victim-org secrets. This is a genuine authentication/authorization boundary bypass across tenants in a multi-org Shipit install, matching the "escalation into `Shipit.github_teams` authorization" High/Critical impact category. It is repeatable against any `Team` row whose `github_id` the attacker can predict or enumerate (team ids are visible via public GitHub API/team page URLs), and blast radius extends to every stack gated behind that team's authorization.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment (`Shipit.github_organizations` > 1) where the attacker legitimately operates one of the configured orgs/GitHub Apps (thus knows that org's `webhook_secret`), and (2) knowledge of the victim `Team`'s GitHub numeric team `id` (obtainable via GitHub's public team API/UI for any team the attacker can view, or by brute-force since it's a normal integer). No compromise of victim secrets is needed. This is a realistic scenario for organizations that intentionally support multiple GitHub orgs against one Shipit instance (a supported, documented feature — see `test/dummy/config/secrets_double_github_app.yml`), making the precondition plausible rather than purely theoretical.

### Recommendation
Scope the `Team` lookup/update to the authenticating organization: change `find_or_create_team!` to query by `github_id: params.team.id, organization: params.organization.login` (or better, verify `params.organization.login == repository_owner` / the org resolved during signature verification before touching any `Team`), and reject/raise if an existing `Team` with that `github_id` belongs to a different organization than the one that signed the request.

### Proof of Concept
```ruby
test "cross-org membership webhook cannot mutate another org's team" do
  victim_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id: 1
  Shipit.stubs(:github_teams).returns([victim_team])

  @request.headers['X-Github-Event'] = 'membership'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulate attacker-org's own valid signature

  payload = {
    action: 'added',
    team: { id: victim_team.github_id, name: 'Fake', slug: 'fake', url: 'https://example.com' },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker-login' }
  }.to_json

  assert_no_difference -> { Membership.where(team_id: victim_team.id).count } do
    post :create, body: payload, as: :json
  end

  attacker = Shipit::User.find_by(login: 'attacker-login')
  refute attacker&.authorized?, "attacker must not gain authorization via a forged cross-org membership webhook"
end
```
Both sides of the binding differ before the fix (`repository_owner == 'attacker-org'` vs `victim_team.organization == 'shopify'`) yet the mutation still occurs, confirming the vulnerability; the fix should make the handler refuse to mutate the team when these diverge.

### Citations

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** test/dummy/db/schema.rb (L342-351)
```ruby
  create_table "teams", force: :cascade do |t|
    t.string "api_url", limit: 255
    t.datetime "created_at", null: false
    t.bigint "github_id"
    t.string "name", limit: 255
    t.string "organization", limit: 39
    t.string "slug", limit: 255
    t.datetime "updated_at", null: false
    t.index ["organization", "slug"], name: "index_teams_on_organization_and_slug", unique: true
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
