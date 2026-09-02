### Title
Global, repository-unscoped commit lookup in `StatusHandler` lets an operator of any registered GitHub organization write commit statuses onto stacks owned by a different organization - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a `status` webhook against the HMAC secret configured for a single GitHub organization/app (`repository_owner`, derived from `payload.dig('repository','owner','login')`), but `StatusHandler#process` never re-checks that binding when deciding which `Commit` records to mutate. It performs a global, unscoped `Commit.where(sha: params.sha)` lookup across the entire database, so the "organization whose signature was verified" and the "repository/commit that gets written to" are two different, unchecked values — the exact class of bug in the report (a value that influences a privileged effect but is never covered by the checked/verified quantity).

### Finding Description
`WebhooksController#verify_signature` resolves the GitHub App/secret to check against using only `repository_owner`: [1](#0-0) [2](#0-1) 

Once the signature for that organization's webhook secret is valid, the raw JSON body is dispatched unchanged to the registered handler: [3](#0-2) 

Other handlers (e.g. `PushHandler`, `CheckSuiteHandler`) correctly re-derive the acted-upon repository from the payload and scope their side effects through `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)`: [4](#0-3) [5](#0-4) [6](#0-5) 

`StatusHandler`, however, does not use `stacks`/`repository_name` at all. It queries `Commit` globally by `sha` with no repository or stack filter, then writes a status onto every matching commit found anywhere in the instance: [7](#0-6) 

This breaks the binding: `organization whose webhook secret authenticated the request == repository/stack that gets mutated`. The `state` field written by `create_status_from_github!` directly influences `Commit#deployable?`, and `Status` creation triggers `schedule_continuous_delivery`/`enable_ci_on_stack`, which can enable or unblock automatic deployment of the target stack: [8](#0-7) [9](#0-8) 

### Impact Explanation
A GitHub organization owner/admin who legitimately controls a Shipit-configured GitHub App/webhook for their own organization (e.g. `org-a`) can install/trigger a `status` event carrying an arbitrary `sha`. Because `Commit.where(sha:)` is global and unscoped, if a commit with a colliding/known SHA exists under a completely different organization's stack (`org-b`), the attacker's authenticated-for-`org-a` webhook can create a `success`/`failure` `Status` on `org-b`'s commit. Since `Status` creation can flip `Commit#deployable?` to `true` and trigger `schedule_continuous_delivery`, an attacker who only controls webhook signing for their own org can influence whether an unrelated organization's stack becomes eligible for (and gets) an unauthorized continuous deployment — a cross-organization/cross-repository write with deploy-triggering consequences, without ever holding credentials for `org-b`.

### Likelihood Explanation
Exploitation requires the attacker to know or guess a real SHA of a commit tracked by another organization's stack. In real-world usage, commit SHAs are often shared/known (e.g., mirrored open-source repos, forked stacks, or SHAs leaked via public commit histories, PRs, or other Shipit API responses that are not access-controlled to the org). Given that this engine is explicitly designed to host stacks for many different GitHub organizations behind a single instance (see the multi-org `github:` config in the setup docs), and that any org that can install/webhook their own repo can trigger this handler, the likelihood is non-trivial for any multi-tenant Shipit deployment.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler`/`CheckSuiteHandler` do: resolve the stack(s) via `stacks` (derived from `payload.dig('repository','full_name')`) and restrict the `Commit` lookup to `stack.commits.where(sha: params.sha)` instead of a global `Commit.where(sha:)`. This ensures the repository whose webhook secret was verified is the same repository whose commit-status state is mutated.

### Proof of Concept
1. Shipit is configured with GitHub Apps for two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (as shown in the multi-org docs).
2. `org-b` has a stack tracking a commit with SHA `abc123...` (known to the attacker, e.g. via a public mirror or a previous API response).
3. The attacker, who administers the GitHub App for `org-a`, sends a `status` webhook to Shipit with `X-Github-Event: status`, a valid `X-Hub-Signature` computed with `org-a`'s webhook secret, and body:
```json
{
  "sha": "abc123...",
  "state": "success",
  "context": "ci/attacker",
  "repository": {"owner": {"login": "org-a"}}
}
```
4. `WebhooksController#verify_signature` validates the signature against `org-a`'s secret and passes.
5. `StatusHandler#process` executes `Commit.where(sha: "abc123...")`, which matches `org-b`'s commit (since the query is unscoped), and calls `commit.create_status_from_github!(params)`, creating a `success` status on `org-b`'s commit and potentially triggering `schedule_continuous_delivery` for `org-b`'s stack — all without any credential or access to `org-b`.

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
