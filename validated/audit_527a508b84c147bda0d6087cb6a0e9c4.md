### Title
Webhook signature verified against `repository.owner.login`, but handlers act on the distinct `repository.full_name` field — organization/repository binding mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a GitHub webhook against based on `repository.owner.login` (or `organization.login`) read straight from the unauthenticated JSON body, then verifies `X-Hub-Signature` against that secret. [1](#0-0) [2](#0-1)  Once the request is accepted, every handler determines *which repository/stacks to mutate* using a different field from the same body: `payload.dig('repository', 'full_name')`. [3](#0-2)  Neither field is cryptographically bound together by the signature (the signature only proves the *body as a whole* was signed with *some* organization's secret, not that `owner.login` and `full_name` refer to the same tenant).

### Finding Description
In a multi-organization Shipit deployment (`Shipit.github_organizations` supports multiple orgs, each with its own `webhook_secret`, as shown in `test/dummy/config/secrets_double_github_app.yml`), each organization owner independently registers a GitHub App/webhook against the shared Shipit instance and knows their own `webhook_secret`. [4](#0-3) [5](#0-4) 

The controller picks the verification secret using `repository_owner`, taken from the attacker-controlled JSON body *before* the signature check occurs:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

An org owner "Org A" (a legitimate, unprivileged-relative-to-Org-B tenant who only knows Org A's `webhook_secret`) can sign an arbitrary JSON body with that secret and set:
- `repository.owner.login = "OrgA"` → makes `verify_signature` pick Org A's `webhook_secret` and pass.
- `repository.full_name = "OrgB/target-repo"` → makes every `Handler#stacks` / `Repository.from_github_repo_name` lookup resolve to Org B's tracked repository/stacks instead. [3](#0-2) 

The equality the code implicitly (and incorrectly) assumes is:
`organization whose secret authenticated the request == organization that owns the repository being mutated`

But nothing enforces `repository.owner.login == repository.full_name.split('/').first`. This lets Org A forge webhook events that are processed as if they came from GitHub for Org B's repositories.

Concretely reachable handlers include:
- `PushHandler#process`, which finds Org B's stacks by branch and calls `stack.sync_github(expected_head_sha: params.after)` — able to force sync/deploy-trigger state changes on someone else's stack using an attacker-chosen `after` SHA. [6](#0-5) 
- `MembershipHandler#process`, which creates/updates a `Team` (setting `team.organization = params.organization.login`, itself attacker-controlled) and adds/removes an arbitrary GitHub login as a member of that team. [7](#0-6)  Since `Shipit.github_teams` (OAuth team authorization) is derived from these `Team`/`Membership` records, this is a direct path to escalate an arbitrary GitHub user into a privileged team's membership, bypassing GitHub-side team management entirely.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary called out explicitly as in-scope. The worst-case outcome — forging `membership` events to insert an arbitrary GitHub login into a `Team` that backs `Shipit.github_teams` — is an escalation into `Shipit.github_teams` authorization, matching the High severity bar. It also enables cross-repository/cross-tenant writes (forcing `sync_github` on another organization's stacks), which is explicitly listed as Critical impact.

### Likelihood Explanation
This requires the attacker to be an onboarded/legitimate organization admin on the Shipit instance (i.e., they possess a valid `webhook_secret` for *their own* org) but have no authorization over the *victim* org's stacks/teams — exactly the "unprivileged attacker breaking a deployment-trust binding" scope described. No repository write access, `ApiClient` token, or GitHub App private key for the victim org is required; only the ability to send a raw HTTP POST to `/webhooks` with a validly-signed-for-their-own-org body.

### Recommendation
Bind the field used to select the verification secret to the field used for repository resolution: after signature verification succeeds, re-derive the organization strictly from `repository.full_name`'s owner segment (or vice versa) and reject the webhook if they don't match, rather than trusting two independent, unauthenticated fields of the same JSON body for two different security decisions.

### Proof of Concept
1. Attacker controls "OrgA" on the shared Shipit instance and knows `webhook_secret_A` (configured when they created their GitHub App integration).
2. Attacker builds a JSON payload for the `membership` event:
```json
{
  "action": "added",
  "team": {"id": 999, "name": "Victim Admins", "slug": "victim-admins", "url": "https://example.com"},
  "organization": {"login": "OrgB"},
  "member": {"login": "attacker-controlled-login"},
  "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo"}
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_A, body)` and POSTs to `/webhooks` with `X-Github-Event: membership`.
4. `verify_signature` reads `repository.owner.login == "OrgA"`, fetches `Shipit.github(organization: 'OrgA')`, and the HMAC matches → request accepted. [1](#0-0) 
5. `MembershipHandler#process` creates/updates `Team(organization: "OrgB", ...)` and adds `attacker-controlled-login` as a member, even though the request was never signed by OrgB. [7](#0-6) 

*(Note: I was unable to fully verify how `Shipit.github_teams` maps `Team`/`Membership` records into session-level authorization checks — that logic lives outside the files retrieved in this investigation, so the exact downstream authorization impact should be confirmed by reading `Shipit.github_teams`'s consumers before treating this as fully proven end-to-end.)*

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** lib/shipit/github_app.rb (L44-57)
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
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
