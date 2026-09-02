### Title
Webhook signature is verified against one organization while the payload's `repository.full_name`/commit `sha` used to select the target Stack is completely uncorrelated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` derives the GitHub App/organization whose `webhook_secret` is used to validate the HMAC signature from `repository.owner.login` (falling back to `organization.login`) in the JSON body itself. [1](#0-0) [2](#0-1)  Once the signature validates for that organization, the raw parsed body is dispatched unmodified to event handlers. [3](#0-2)  Those handlers select the target `Stack`/`Commit` using a *different* field of the same attacker-supplied body: `payload.dig('repository', 'full_name')` for `push`/`pull_request`/`check_suite` handlers, [4](#0-3)  or, in the case of `StatusHandler`, no repository scoping at all - just a global `Commit.where(sha: params.sha)` lookup. [5](#0-4) 

Because Shipit explicitly supports hosting multiple GitHub organizations behind one instance, each with its own independent `webhook_secret`, [6](#0-5)  an attacker who legitimately controls one low-trust organization's GitHub App (and therefore knows *that* organization's `webhook_secret`) can sign an arbitrary JSON body with it. Nothing binds the organization used for signature verification to the repository/commit that the handler actually mutates.

### Finding Description
The authentication binding that should hold is:
`organization whose webhook_secret validated the signature == organization/repository the handler acts upon`

This binding is broken because:
1. `verify_signature` picks the signing secret via `repository_owner`, which reads `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [2](#0-1) 
2. The signature itself is computed over the *entire* raw HTTP body (`OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message)`), so any body field, including `repository.full_name` or `sha`, is technically "covered" by the HMAC - but the HMAC only proves the message came from someone who knows *the org selected by `repository_owner`*, not that this org is the actual owner of every other field. [7](#0-6) 
3. Handlers never re-check that `repository.owner.login` (used for auth) matches the owner segment of `repository.full_name` (used for target resolution): `Handler#repository_name` just returns `payload.dig('repository', 'full_name')` and looks up `Repository.from_github_repo_name`. [4](#0-3) 
4. `StatusHandler` is worse: it doesn't even use `repository_name`/`stacks` - it looks up `Commit.where(sha: params.sha)` globally across the whole Shipit instance and creates a `Status` on every matching commit, regardless of which stack/organization it belongs to. [5](#0-4) 

So an attacker who administers an organization "Org A" that is configured on this Shipit instance (and thus knows Org A's `webhook_secret`) can craft a webhook payload with `repository.owner.login = "OrgA"` (so `verify_signature` succeeds using Org A's secret) but with `repository.full_name = "OrgB/target-repo"` or an arbitrary `sha` belonging to Org B's commits (a repository/organization the attacker has no access to and whose secret they do not know). The forged, validly-signed request will still be processed against Org B's stack.

### Impact Explanation
This crosses the "organization that authenticated vs. the repository that is written" trust boundary explicitly called out as an equality that must not be broken. Concretely:
- Via `StatusHandler`, an attacker can inject a fabricated commit `Status` (state, `target_url`, `description`, `context`) onto any commit of any stack across the entire instance, without needing that stack's org secret. [5](#0-4)  Commit statuses feed into `Commit`'s `required_statuses`/`blocking_statuses` (delegated to `Stack`) which gate whether a commit is considered deployable in Shipit's UI/API. [8](#0-7)  Forging a passing status for another organization's commit can help an attacker (or someone colluding with a legitimate deployer) make an otherwise-blocked/failing commit appear deployable, enabling an unauthorized deploy decision on infrastructure they don't control the GitHub org for.
- Via `PushHandler`/`CheckSuiteHandler`, an attacker can trigger `GithubSyncJob`/`RefreshCheckRunsJob` against an arbitrary victim stack identified by `repository.full_name`, forcing sync activity or check-run refresh cycles on a repository outside their authorization scope. [9](#0-8)  While the actual commit data fetched is pulled from GitHub itself (limiting direct code injection), this is still an unauthorized cross-organization action triggered purely by knowledge of a different (unrelated) org's webhook secret.

This satisfies the "unauthorized deploy" / cross-repository-write impact bar, given deploy-gating status data can be manipulated cross-organization.

### Likelihood Explanation
Requires:
- The Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration). [6](#0-5) 
- The attacker to control a GitHub App installation (and therefore its `webhook_secret`) for at least one of the configured organizations - a realistic scenario in shared/multi-tenant Shipit deployments where different teams/orgs each administer their own GitHub App but share one Shipit backend.
- No special privilege on the victim organization/repository is required; the attacker never needs the victim's secret, GitHub token, or Shipit session - only network access to `POST /webhooks` with a body they sign themselves.

### Recommendation
After computing `verified` in `verify_signature`, cross-check that the organization/owner used to select the `webhook_secret` matches the owner embedded in every field the handlers will act on (e.g., derive the owner from `repository.full_name` and require it equal `repository.owner.login`/`organization.login` before dispatch). Additionally, `StatusHandler` should scope `Commit.where(sha: params.sha)` to commits whose `stack.repository` matches the verified organization/repository, rather than searching globally across all tenants.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` and `OrgB`, each with distinct `webhook_secret`s (per the documented multi-org config). [6](#0-5) 
2. As an administrator of `OrgA`'s GitHub App, obtain `OrgA`'s `webhook_secret` (legitimately known to the attacker as the org's own app owner).
3. Craft a `status` event JSON body:
```json
{
  "sha": "<sha-of-a-commit-belonging-to-OrgB-stack>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" } }
}
```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and successfully verifies the signature using `OrgA`'s secret. [1](#0-0) 
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` - matching the OrgB commit regardless of the fact the signature was verified for OrgA - and calls `commit.create_status_from_github!(params)`, creating a forged "success" status on a commit the attacker has no authorization over. [5](#0-4)

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/models/shipit/commit.rb (L57-58)
```ruby
    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
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
