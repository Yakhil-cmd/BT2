### Title
Webhook signature verification selects the signing key from unverified payload data, decoupling "organization authenticated" from "repository written" - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate the HMAC against by reading `repository_owner` straight out of the *unverified* JSON body, before the signature is checked. In a multi-organization Shipit deployment (a documented, supported configuration), each organization can have its own `webhook_secret`, and that secret is optional per-org. An attacker can craft a payload claiming to be from an organization whose `webhook_secret` is blank/unset, which makes signature verification a no-op, while the handler that actually mutates state (e.g. `StatusHandler`) trusts other attacker-controlled fields (`sha`) that are not scoped to the "authenticated" organization at all. This breaks the binding: *organization whose secret authenticated the request* == *repository/commit actually written to*.

### Finding Description
`WebhooksController#verify_signature` computes the signing organization from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` — a field inside the raw, unauthenticated request body — and is used to select which `GitHubApp` (and therefore which `webhook_secret`) to verify against via `Shipit.github(organization: repository_owner)`.

`GitHubApp#verify_webhook_signature` explicitly treats a blank secret as "always verified": [3](#0-2) 

`webhook_secret` is documented and shown as an optional/nil-able field per organization, including in multi-org setups: [4](#0-3) [5](#0-4) 

So if any one configured organization in a multi-org Shipit instance has no `webhook_secret` set, an attacker can send `POST /github/webhooks` claiming `repository.owner.login` = that organization, and `verify_signature` will accept the request unconditionally — no secret, token, or session required.

Once "verified," the actual event handler doesn't re-check that the claimed organization matches the resource being mutated with the same rigor. `Handler#stacks` derives the acted-upon repository from `payload.dig('repository', 'full_name')` (a sibling field the attacker also fully controls) rather than from anything cryptographically tied to the verified organization: [6](#0-5) 

Worse, `StatusHandler` doesn't even go through `stacks`/repository scoping — it looks up commits globally by `sha` across the entire database: [7](#0-6) 

Since commit SHAs are public (visible in any git history/PR), an attacker can forge a `status` webhook event for a commit belonging to a completely different, properly-secured organization/stack, using only the blank-secret organization to pass the HMAC check. This directly calls `Commit#create_status_from_github!`, which writes a `Status` record used by deploy-safety/CI gating and by `ContinuousDeliveryJob` (`stack.continuous_deployment?`, `stack.trigger_continuous_delivery`): [8](#0-7) 

The equality broken here is: *organization whose `webhook_secret` authenticated the request* should equal *organization/repository the mutating handler acts on*. Instead, the "authenticating" field and the "acted upon" field are two independently attacker-controlled fields in the same unverified JSON body — the signature check only proves the payload was accepted under one org's (possibly absent) secret, not that the referenced repository/commit belongs to that org.

### Impact Explanation
An unprivileged attacker with no Shipit session, no `ApiClient` token, and no knowledge of any real `webhook_secret` can forge GitHub webhook events (`status`, `push`, `pull_request`, etc.) that are processed as if legitimately delivered, provided the Shipit instance uses the documented multi-organization GitHub App configuration and at least one configured org has no `webhook_secret`. This can inject forged commit statuses that feed into deploy-readiness/CI checks and continuous-deployment triggers for stacks in a *different, properly secured* organization, and can trigger `GithubSyncJob`/`RefreshCheckRunsJob`/etc. for arbitrary tracked repositories via `push`/`check_suite` events. This maps to an unauthorized influence over deploy/rollback gating (continuous deployment relies on commit status), qualifying as High/Critical depending on how CI-gated the target stack's continuous deployment is.

### Likelihood Explanation
Requires: (1) the operator to use the documented multi-org GitHub App config, and (2) at least one configured organization to have an unset `webhook_secret` (shown as the default/example value in `config/secrets.development.example.yml` and `docs/setup.md`, so plausible in real deployments, e.g., a low-risk sandbox org added alongside a production org). Given those conditions, exploitation requires only a single unauthenticated HTTP POST with a known commit SHA — no credentials of any kind.

### Recommendation
Do not let unverified payload fields decide which secret verifies the payload. Either: (a) verify the signature against every configured organization's secret and derive the organization from whichever secret matches (or require exact equality between the signature-selected org and the `repository.full_name` owner after verification), or (b) require a non-blank `webhook_secret` for every configured organization and reject requests where `repository.owner.login` doesn't match `repository.full_name`'s owner segment. Additionally, scope `StatusHandler` (and any other handler) lookups to the repository asserted in the (now properly verified) payload rather than performing a global `Commit.where(sha:)` lookup across all stacks.

### Proof of Concept
Preconditions: Shipit configured with two organizations, e.g. `OrgA` (has `webhook_secret` set, hosts the target production stack) and `OrgB` (no `webhook_secret` configured), similar to `test/dummy/config/secrets_double_github_app.yml`.

```
POST /github/webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything   # ignored because OrgB has no webhook_secret

{
  "sha": "<known public sha of a commit on OrgA's tracked repo>",
  "state": "success",
  "context": "ci/forged",
  "description": "forged",
  "target_url": "https://attacker.example",
  "repository": { "owner": { "login": "OrgB" } }
}
```

`verify_signature` resolves `Shipit.github(organization: "OrgB")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of `X-Hub-Signature`. `StatusHandler#process` then looks up `Commit.where(sha: params.sha)` globally (no organization/repository scoping) and calls `create_status_from_github!`, writing a forged CI status for the OrgA commit — potentially satisfying deploy-readiness checks feeding `ContinuousDeliveryJob`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```
