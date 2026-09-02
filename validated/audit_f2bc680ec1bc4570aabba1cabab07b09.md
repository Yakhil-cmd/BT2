### Title
Webhook signature binds trust to the payload's claimed organization, but event handlers act on unrelated, unchecked repository/commit identifiers from the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook delivery by looking up the GitHub App/secret for the organization named in `repository.owner.login` (or `organization.login`) inside the JSON body, then HMAC-verifying the raw body against that org's `webhook_secret` [1](#0-0) [2](#0-1) . Once the signature check passes, every event handler independently re-reads other, unrelated fields from that same attacker-suppliable JSON body (`repository.full_name`, `sha`, `check_suite.head_sha`/`head_branch`) to decide which `Repository`/`Stack`/`Commit` to mutate [3](#0-2) [4](#0-3) . Nothing ever checks that the organization that produced a valid signature is the same organization that owns the repository/commit being written to. In a multi-tenant Shipit install (multiple orgs each configured under the `github:` key with their own `webhook_secret`, as documented in `docs/setup.md`), any onboarded organization can compute a valid signature for its own secret while filling in a `sha` or `repository.full_name` belonging to a different organization's tracked stack.

### Finding Description
The binding that should hold is: **organization authenticated via HMAC == organization whose repository/commit is written**. The code instead checks:
- `repository_owner` (from payload, used only to pick which secret to verify against) [2](#0-1) 

...but performs the actual database write using a *different, uncorrelated* field from the same untrusted payload:
- `StatusHandler#process` does `Commit.where(sha: params.sha)` with **no repository/organization scoping at all**, then calls `commit.create_status_from_github!(params)`, writing attacker-chosen `state`, `context`, `description`, and `target_url` onto any commit in the entire Shipit install that happens to have that SHA [4](#0-3) .
- Other handlers scope by `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` [3](#0-2)  - a value that is never checked against `repository.owner.login` (the field used to select the verifying secret in the controller). An attacker who controls org A's own webhook secret can therefore submit a payload where `repository.owner.login = "orgA"` (so the signature check passes) while `repository.full_name = "orgB/some-tracked-repo"` or `sha = <commit belonging to orgB>`.

Before vs. after the attacker's crafted request:
- Before: signature check binds "this HTTP request came from org A" to "org A's webhook secret."
- After: the handler acts on data (`full_name`, `sha`) that names org B's repository/commit, with the write performed as if it were a legitimate GitHub-origin event for org B.

This is structurally the same class of bug as the audit finding: an early trust/validation step (max_leverage check / webhook HMAC check) validates one piece of state, while the subsequent state-mutating action (the swap / the DB write) is driven by attacker-controlled data that was never covered by, or cross-checked against, that validation.

### Impact Explanation
Via `StatusHandler`, a forged `success` status on another organization's commit can:
- Flip `MergeRequest#all_status_checks_passed?` (used by `ProcessMergeRequestsJob`) to true, causing `merge_request.merge!` to execute an **unauthorized merge** on a repository the attacker never had access to [5](#0-4) [6](#0-5) .
- Satisfy `deployable?`/continuous-delivery gating for a stack with `continuous_deployment: true`, triggering an **unauthorized deploy** of another organization's code.

This meets the Critical bar explicitly listed in scope rules ("an unauthorized deploy, rollback or merge"), reached purely as an unprivileged cross-tenant attacker (control of one's own onboarded org's GitHub App/webhook secret, not any Shipit credential, `ApiClient` token, or repository write access on the victim org).

### Likelihood Explanation
Requires a Shipit instance configured with more than one GitHub organization sharing the deployment (explicitly supported and documented, e.g. `config/secrets.development.shopify.yml` and the multi-org test fixture `secrets_double_github_app.yml`) [7](#0-6) . Any organization admin in that shared install already legitimately knows their own org's `webhook_secret` (it's something they configured), and only needs to know the target SHA of a commit in another tracked stack (discoverable via that stack's public GitHub repo/CI or Shipit UI) to forge the request. No exploitation of GitHub's mempool/sandwiching mechanics is needed - this is a direct, deterministic cross-tenant write once the attacker's own secret is known, making it straightforward to execute reliably.

### Recommendation
In `Handler#stacks`/`repository_name` and especially in `StatusHandler`/`CheckSuiteHandler`, require that the organization used to verify the webhook signature (`repository_owner` in `WebhooksController`) matches the owner of the repository/stack being mutated before performing any write. Concretely: pass the verified organization through to each handler and assert `stack.repository.owner == verified_organization` (case-insensitively) before calling `create_status_from_github!`, `schedule_refresh_check_runs!`, or any other stack-mutating operation. For `StatusHandler`, scope the `Commit` lookup by stack/repository rather than global `sha` alone.

### Proof of Concept
1. Attacker administers organization `orgA`, onboarded to the shared Shipit instance with `webhook_secret = S`.
2. Attacker computes `sig = HMAC-SHA1(S, body)` for a crafted JSON body:
```json
{
  "sha": "<head sha of a commit belonging to orgB's tracked stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/irrelevant" }
}
```
3. POST to `/webhooks` with header `X-Github-Event: status` and `X-Hub-Signature: sha1=sig`.
4. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "orgA")` and successfully verifies the signature [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching orgB's commit — and calls `create_status_from_github!(params)`, injecting a forged `success` status onto orgB's commit [4](#0-3) .
6. On orgB's stack, `ProcessMergeRequestsJob` subsequently observes `all_status_checks_passed?` as true and executes `merge_request.merge!`, merging a pull request into orgB's repository without orgB's consent.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-26)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
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
