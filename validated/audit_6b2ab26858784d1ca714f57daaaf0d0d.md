### Title
Webhook Signature Verified Against `repository.owner.login` While Handlers Act On `repository.full_name` — Cross-Repository Write via Org/Repo Binding Mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate the HMAC signature against using `repository.owner.login` from the JSON body, but every webhook handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, and the `PullRequest::*Handler`/`ReviewStackAdapter` classes) resolves the target `Repository`/`Stack` to mutate using the separate `repository.full_name` field from the same body. Because the HMAC covers the raw body but is looked up per-organization by a field that is never cross-checked against the field actually used to select the mutated record, an attacker who legitimately controls a webhook secret for *any* one configured organization can forge a validly-signed payload whose `repository.full_name` names a *different* organization's repository.

### Finding Description
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` via `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) , and uses it to fetch the corresponding `GithubApp`/secret: `Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(...)` [2](#0-1) . In a multi-organization Shipit deployment, each organization key in `secrets.github` has its own `webhook_secret` (`lib/shipit/github_app.rb:44-50`, `lib/shipit.rb:196-200`) — i.e., each org owner independently knows/configures the secret used to sign hooks for their own org.
- Once signature verification passes, `create` dispatches the entire raw JSON body to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .
- Every handler resolves the mutated `Repository`/`Stack` from `payload.dig('repository', 'full_name')`, not from `repository.owner.login`: [4](#0-3) . The `PullRequest` handlers likewise pull `params.repository.full_name` to look up `Repository.from_github_repo_name` and act on `review_stacks`/`stacks` [5](#0-4) .
- `Repository.from_github_repo_name` splits `owner/name` straight out of `full_name` and does a DB lookup with no relation back to the organization used for signature verification: [6](#0-5) .

**The broken equality**: the engine implicitly assumes `repository.owner.login == owner(repository.full_name)`, but nothing enforces it. An attacker who knows the webhook secret for organization **A** (which they legitimately administer/configured in GitHub) can send a payload where `repository.owner.login = "A"` (making `verify_signature` pick org A's secret, which the attacker used to correctly sign the raw body) while `repository.full_name = "B/victim-repo"` targets organization **B**'s repository/stack. Handlers will act on organization B's `Stack`/`Repository`/`Commit`/`ReviewStack` records using data validated only against organization A's key.

### Impact Explanation
This breaks the deployment-trust boundary between organizations in a multi-tenant Shipit instance: attacker-controlled `push`, `status`, `check_suite`, `pull_request`, or `membership` webhooks aimed at organization A can instead:
- Trigger `stack.sync_github(expected_head_sha: ...)` for a victim org's branch/stack via `PushHandler` [7](#0-6) .
- Inject fabricated commit statuses for arbitrary commits via `StatusHandler#process` (`Commit.where(sha: params.sha)` is not scoped by owning stack/org at all) [8](#0-7) , which can gate `continuous_delivery`/auto-deploy decisions on `Stack`.
- Archive/unarchive or create review stacks belonging to a victim organization's repository through the `PullRequest::*Handler` classes and `ReviewStackAdapter`, which provision/deprovision infrastructure [9](#0-8) .

This is a cross-organization/cross-repository write against Stack/Commit/ReviewStack state that the requester does not own, satisfying the "cross-repository writes" / "unauthorized deploy" impact bar, contingent on the deployment running multiple organizations with independently-controlled webhook secrets.

### Likelihood Explanation
Requires: (1) Shipit configured for multiple GitHub organizations (`secrets.github` keyed by org, each with its own `webhook_secret`), and (2) the attacker legitimately controls at least one organization/repo already registered with this Shipit instance (so they know that org's `webhook_secret` and can send a signed request). This is a materially different — and typically much weaker — precondition than "repository write access to the victim repo" or "an ApiClient token," which are the out-of-scope preconditions this scan explicitly excludes. It does not require the host application to deviate from documented mounting.

### Recommendation
After signature verification succeeds, cross-check that `repository.owner.login` (the org whose secret validated the payload) matches the owner encoded in `repository.full_name` before dispatching to handlers, and reject the request otherwise. Alternatively, derive `repository_owner` for signature lookup from the same `full_name` field the handlers use, so a single canonical field governs both which secret verifies the payload and which repository is mutated.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `orgA` and `orgB`, each with its own repository/stack and its own `webhook_secret` in `secrets.github`.
2. As the legitimate administrator of `orgA` (who knows orgA's webhook secret), craft a `push` (or `status`/`pull_request`) webhook JSON body with:
   - `repository.owner.login = "orgA"`
   - `repository.full_name = "orgB/victim-repo"`
3. Sign the raw JSON body with `orgA`'s `webhook_secret` using HMAC-SHA1 and set `X-Hub-Signature` accordingly; set `X-Github-Event` to the target event.
4. POST to `/webhooks`. `verify_signature` looks up `Shipit.github(organization: "orgA")`, verifies successfully against the attacker-known secret [2](#0-1) .
5. The dispatched handler resolves the target repository via `repository.full_name` = `"orgB/victim-repo"` [4](#0-3)  and performs the corresponding write (sync, status creation, or review-stack archive/unarchive) against `orgB`'s stack, despite the request never being validated with `orgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-50)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```
