### Title
`MembershipHandler#process` deletes `Membership` rows by `Team#github_id` alone, with no check that the deleting webhook's organization matches `team.organization` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#process` resolves the target `Team` solely via `Team.find_or_create_by!(github_id: params.team.id)` and, on `action == 'removed'`, calls `team.members.delete(member)` without ever verifying that `params.organization.login` (the org whose secret validated the webhook signature) equals `team.organization` (the org that actually owns that `Team` row) [1](#0-0) . This lets a party who controls the webhook secret for ORG_B forge a `membership`/`removed` payload naming a `Team#github_id` that belongs to ORG_A, deleting a real `User`'s membership row for that team.

### Finding Description
The broken binding, stated as an equality that the code never checks: `params.organization.login == team.organization` must hold before mutating `team.members`, but `MembershipHandler#process` never evaluates this equality.

Trace:
- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and HMAC-verifies the raw body against **that org's** configured `webhook_secret` [2](#0-1) . For `membership` events GitHub sends no `repository` key, so `repository_owner` falls back to `params.dig('organization', 'login')` [3](#0-2) . This means the signature only proves "whoever sent this knows ORG_B's `webhook_secret`" (each configured org has its own independent secret, per `GitHubApp#initialize`/`verify_webhook_signature` and the multi-org secrets schema) [4](#0-3) . It does **not** bind the signature to the contents of `params.team.id` or to any other org named inside the body.
- `MembershipHandler#find_or_create_team!` looks the `Team` up **only** by `github_id`; `params.organization.login` is used solely inside the `create!` block when the record doesn't yet exist [5](#0-4) .
- `process` then branches on `params.action`; for `'removed'` it runs `team.members.delete(member)` unconditionally [6](#0-5) , deleting the `Membership` join row (`memberships` table, unique on `[team_id, user_id]`) regardless of which org the request claims to be from.

Exploit flow: attacker administers ORG_B, a Shipit-registered organization with its own `webhook_secret`. They already legitimately know that secret (they configured Shipit's GitHub App for their own org). They POST to `/webhooks` with `X-Github-Event: membership`, a body of `{"action":"removed","team":{"id":<ORG_A's privileged team's github_id>,...},"organization":{"login":"org_b"},"member":{"login":"victim"}}`, and `X-Hub-Signature` computed with ORG_B's `webhook_secret` over that exact body. `verify_signature` resolves `Shipit.github(organization: "org_b")` and successfully verifies the signature (it never inspects `params.team.id`). `find_or_create_team!` then looks up the pre-existing `Team` row for ORG_A's real team by `github_id` and returns it. `process` deletes `victim`'s `Membership` on that team.

Existing guards do not close this gap: `verify_signature` authenticates the sender-organization identity but not the payload's cross-references to other orgs' resources; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape/presence of fields, not tenant ownership; there is no `require_permission!`/`Stack`-scoped check in this handler at all, since `membership` webhooks are org-level, not repository/stack-scoped.

### Impact Explanation
The attacker can deauthorize an arbitrary real `User` from `Shipit.github_teams` by deleting their `Membership` row on a privileged team, since `User#authorized?` checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6) . This is a genuine cross-tenant write: a request "verified" for ORG_B mutates a `Membership` row belonging to ORG_A's `Team`. It is repeatable against any `Team#github_id` the attacker can learn (team IDs are exposed via GitHub's `org_teams` API and other channels), decrementing `Membership.count` for any target team without their org's own secret. Per the question's own framing this is a deauthorization rather than an escalation into `Shipit.github_teams`, so its direct impact is denial-of-access to a legitimate authorized user rather than granting the attacker new privileges — it does not itself achieve RCE, credential exfiltration, or an unauthorized deploy/merge, and does not escalate the attacker into a privileged team.

### Likelihood Explanation
Preconditions: the attacker must control (or be the configured admin of) an organization that Shipit has been configured to trust with its own `webhook_secret` in the multi-org `github:` secrets schema (as documented, only feasible in installations serving multiple, potentially mutually-distrusting organizations) [8](#0-7) . They also need to know or guess the numeric `github_id` of the target `Team` already persisted in Shipit's database (learnable via GitHub's team API for teams they can see, or via prior legitimate `added` webhooks). Given those two facts, forging the request is a single unauthenticated HTTP POST with a correctly computed HMAC using a secret the attacker legitimately possesses for their own org — cheap and repeatable.

### Recommendation
In `MembershipHandler#process` (and `find_or_create_team!`), require that `params.organization.login.downcase == team.organization` before performing any mutation, and raise/drop the event (or create a distinct `Team` scoped by both `github_id` and `organization`) when they diverge, mirroring the tenant-scoping already implicit in `Team.find_or_create_by_handle`'s `organization:, slug:` lookup.

### Proof of Concept
```ruby
test ":membership can't delete membership on another org's team with a colliding github_id" do
  org_a_team = shipit_teams(:shopify_developers) # organization == 'shopify'
  membership = Membership.create!(team: org_a_team, user: shipit_users(:walrus))

  @request.headers['X-Github-Event'] = 'membership'
  body = {
    action: 'removed',
    team: { id: org_a_team.github_id, name: org_a_team.name, slug: org_a_team.slug, url: org_a_team.api_url },
    organization: { login: 'org_b' }, # different org than org_a_team.organization
    member: { login: shipit_users(:walrus).login }
  }.to_json

  Shipit.github(organization: 'org_b').expects(:verify_webhook_signature).returns(true)

  assert_no_difference -> { Membership.count } do
    post :create, body:, as: :json
    assert_response :ok
  end
end
```
This currently fails (i.e., `Membership.count` decreases by 1) because `MembershipHandler#process` deletes the membership without checking `team.organization == 'org_b'`.

### Citations

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

**File:** lib/shipit/github_app.rb (L44-83)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end

    def login
      raise NotImplementedError, 'Handle App login / user'
    end

    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end

    def api_status
      conn = Faraday.new(url: 'https://www.githubstatus.com')
      response = conn.get('/api/v2/components.json')
      parsed = JSON.parse(response.body, symbolize_names: true)
      parsed[:components].find { |c| c[:id] == API_STATUS_ID }
    end

    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
