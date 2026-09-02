### Title
Webhook signature verified against `repository.owner.login`, but write scope keyed on `repository.full_name`/global fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to verify a webhook against based on `repository.owner.login` taken from the *same untrusted JSON body* it is about to verify, but every event handler that subsequently executes uses different fields of that body (`repository.full_name`, or nothing at all) to decide which `Stack`/`Repository`/`Commit`/`Team` to mutate. The signature only proves "this payload was signed by the organization whose login appears in `repository.owner.login`" - it proves nothing about which repository's data is actually written.

### Finding Description
`Shipit::WebhooksController#verify_signature` computes the verifying app as: [1](#0-0) 
using `repository_owner`: [2](#0-1) 

Shipit supports multiple GitHub organizations configured with independent `webhook_secret` values in the same engine instance: [3](#0-2) 

`Hook::DeliverySigner`/`GitHubApp#verify_webhook_signature` only proves the request was HMAC-signed with the secret belonging to whatever org `repository.owner.login` says, it does not bind the signature to the rest of the payload's semantic meaning beyond raw bytes: [4](#0-3) 

After signature verification passes, `create` dispatches the parsed body to per-event handlers, all keyed by `X-Github-Event`, without any additional check that the payload's `repository` matches the organization used for verification: [5](#0-4) 

Handlers such as `PushHandler` and `CheckSuiteHandler` resolve the target `Stack` via `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` - a distinct field from `repository.owner.login` used for signing: [6](#0-5) [7](#0-6) [8](#0-7) 

`StatusHandler` doesn't even scope by repository at all - it matches commits globally by SHA across every stack in the installation: [9](#0-8) 

`MembershipHandler` similarly trusts `params.organization.login` (a field never checked against the signing org) to create/attach `Team`/`User` records that gate `Shipit::Authentication#force_github_authentication`'s `authorized?` check: [10](#0-9) [11](#0-10) 

**The broken binding:** `verified organization (repository.owner.login, checked against webhook_secret) == organization/repository whose data the handler mutates (repository.full_name / commit sha / organization.login in a nested object)`. These are separate JSON fields inside one HMAC-signed blob; the signature proves the blob's integrity but the app conflates "signed by org X" with "therefore safe to apply to whatever repo/commit/team the rest of the JSON names," which need not be org X's own resources.

An attacker who legitimately administers **any** GitHub organization/App that is configured in this same multi-tenant Shipit instance (i.e., knows their own org's `webhook_secret`, a normal, unprivileged capability for that org's own admins - no Shipit session or target-repo access required) can craft an arbitrary JSON body, set `repository.owner.login` to their own org (to pass the signature check with their own secret) while setting `repository.full_name`, `check_suite.head_sha`, `sha`, or `organization.login`/`team` fields to point at a completely different, unrelated stack/repository/commit/team, sign it with their own secret, and POST it to the shared `/webhooks` endpoint.

### Impact Explanation
This breaks the intended per-organization isolation of the webhook trust boundary in a multi-org Shipit deployment, allowing cross-repository/cross-organization writes: forcing an unrelated stack's `sync_github` (fetching/enqueueing arbitrary head SHAs), creating/altering commit statuses on arbitrary commits across the whole install (`StatusHandler`), or fabricating team membership records tied to an arbitrary GitHub organization/team (`MembershipHandler`), which downstream governs the `Shipit.github_teams` authorization check used to grant application access. This matches the "cross-repository writes" / "escalation into `Shipit.github_teams` authorization" impact classes.

### Likelihood Explanation
Requires only administrative control of one legitimately-configured GitHub organization's App/webhook secret in the same multi-tenant Shipit install - not a Shipit session, `ApiClient` token, or access to the target repository. In single-organization deployments (the common case) this narrows to no practical impact since there is only one secret/org, but the engine explicitly supports and documents the multi-org configuration shown in `config/secrets.development.shopify.yml`, and the code path performing this org-based secret selection based on payload content is unconditional.

### Recommendation
After signature verification, additionally validate that the `repository.owner.login` (or `organization.login`) used to select the verifying secret matches the `repository.full_name`'s owner (and any nested `organization`/`team` fields) actually acted upon by the handler, rejecting payloads where they diverge; alternatively, pass the verified organization explicitly into each handler and have handlers scope all queries (`Repository.from_github_repo_name`, `Commit.where(sha:)`, `Team.find_or_create_by!`) to that verified organization rather than trusting unrelated fields from the same unauthenticated JSON body.

### Proof of Concept
1. Attacker administers `org-attacker`, configured in Shipit's multi-org `secrets.yml` with `webhook_secret: S`.
2. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-victim/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S, body)`.
4. `WebhooksController#verify_signature` resolves `repository_owner => "org-attacker"`, loads `org-attacker`'s `webhook_secret` (`S`), verification succeeds.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-victim/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker sha>")` on a stack the attacker does not own, using a signature that only proved authorization for `org-attacker`.

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

**File:** config/secrets.development.shopify.yml (L4-23)
```yaml

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
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
