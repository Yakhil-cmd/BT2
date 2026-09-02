### Title
Webhook signature verification authenticates the payload's organization, but event handlers write to a repository/commit selected from an unbound field of the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization secret to use for HMAC verification based on `params.dig('repository','owner','login') || params.dig('organization','login')`, then verifies the raw body against that secret. Every downstream `Webhooks::Handlers::Handler` subclass, however, resolves the target `Repository`/`Stack`/`Commit` from a *different* attacker-controlled field of the same JSON body (`repository.full_name`, or, in the case of `StatusHandler`, simply `sha` with no repository binding at all). Nothing ties the organization whose secret validated the signature to the repository/commit that the handler actually mutates.

### Finding Description
`verify_signature` derives `repository_owner` from the payload and fetches that organization's app config to check the signature: [1](#0-0) [2](#0-1) 

Once verified, the raw body is handed to registered handlers unmodified: [3](#0-2) 

The base `Handler` class (used by `PushHandler`, `CheckSuiteHandler`, all `PullRequest::*Handler`s, etc.) resolves the repository/stacks to act on from `payload.dig('repository', 'full_name')` — a field completely independent from the `repository.owner.login`/`organization.login` used to select the signing secret: [4](#0-3) 

`StatusHandler` is worse: it doesn't even use `repository.full_name` — it looks up and mutates *any* `Commit` in the entire installation purely by `sha`, with zero repository/organization binding whatsoever: [5](#0-4) 

`MembershipHandler` similarly trusts `params.organization.login` for team bookkeeping, independent of whatever organization key validated the request: [6](#0-5) 

The equality that should hold but doesn't:
`organization used to select verify_webhook_signature key == organization/repository whose Stack/Commit state is mutated by the handler`.

In a multi-tenant Shipit deployment (explicitly supported — see `config/secrets.development.shopify.yml` listing multiple orgs each with independent `webhook_secret`), an entity that legitimately administers the GitHub App/webhook for one configured organization (and therefore legitimately knows that organization's `webhook_secret`, which they set up themselves) can sign an arbitrary JSON body with that secret while setting `repository.owner.login`/`organization.login` to their own org (so `verify_signature` passes) and setting `repository.full_name` (or, for `status` events, simply `sha`) to point at a stack/commit belonging to a completely different organization tracked by the same Shipit instance. [7](#0-6) 

### Impact Explanation
This breaks the trust boundary between "who authenticated this webhook" and "what state gets mutated". Concrete effects on stacks/commits the sender has no authority over:
- `StatusHandler` lets the holder of *any* configured org's webhook secret inject a fabricated CI status (e.g. `state: "success"`) onto *any* commit tracked anywhere in the Shipit install, purely by guessing/knowing its SHA (SHAs of public repos are trivially obtainable). Fabricated green statuses can satisfy `required_statuses` checks used to gate deploys, i.e. an unauthorized-deploy escalation path.
- `PushHandler`/`CheckSuiteHandler` let that same actor trigger `GithubSyncJob`/check-run refresh for a victim organization's stack using the victim stack's own GitHub credentials (`stack.github_api`), forcing sync/refresh activity on repositories the caller has no relationship to.
- `MembershipHandler` allows creating/mutating `Team`/`Membership` records under an arbitrary `organization.login`, independent of which org's secret actually signed the request, potentially affecting `Shipit.github_teams` authorization bookkeeping.

This matches the High-impact criteria: escalation into deploy authorization / `Shipit.github_teams` bookkeeping via forged, validly-signed-but-misattributed webhook events.

### Likelihood Explanation
Requires the attacker to control (or be a legitimate but low-privilege admin of) at least one GitHub organization/repository already configured in the same multi-tenant Shipit instance as the victim — a realistic scenario for shared internal deploy tooling serving many teams/orgs, and explicitly documented as supported (`config/secrets.development.shopify.yml` shows multiple independently-keyed orgs in one instance). No GitHub App private key, Shipit session, or API-client token is needed — only the webhook secret of one's own already-registered org, which the rules classify as within scope (not a "privileged account" of the target repository).

### Recommendation
Every `Webhooks::Handlers::Handler` must scope the repository/commit/team it operates on to the *same* organization that was used to select the verifying secret in `WebhooksController#verify_signature`, and that binding should be re-validated inside `Handler#stacks` / `StatusHandler#process` / `MembershipHandler#process` (e.g., reject if `repository.full_name.split('/').first.downcase != repository_owner.downcase`, and scope `StatusHandler`'s `Commit.where(sha:)` lookup by the repository resolved from the verified organization instead of a bare, cross-tenant SHA match).

### Proof of Concept
1. Admin of `OrgA` (already configured in the shared Shipit instance with its own `webhook_secret`) knows `OrgA`'s webhook secret.
2. They craft a JSON body:
```json
{
  "sha": "<sha of a commit belonging to OrgB/victim-repo, tracked as a Stack in the same Shipit instance>",
  "state": "success",
  "repository": { "owner": { "login": "OrgA" } }
}
```
3. Compute `X-Hub-Signature` using `OrgA`'s `webhook_secret` over the raw body, and POST to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature — [1](#0-0) .
5. `StatusHandler#process` matches the commit purely by `sha` (no org check) and creates a fabricated `success` status on the victim's commit — [5](#0-4) , potentially unblocking a deploy that depended on that status check.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
