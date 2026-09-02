### Title
Cross-organization forged commit statuses via unscoped `StatusHandler` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb](app/models/shipit/webhooks/handlers/status_handler.rb))

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook using a per-organization `webhook_secret` selected from the payload's `repository.owner.login` / `organization.login`, but the `status` event handler that then mutates state never re-checks that the commit it edits actually belongs to that same organization/repository. It resolves commits globally by `sha` only, so a signature valid for organization A authorizes writes on commits owned by organization B.

### Finding Description
`verify_signature` picks the `GithubApp` (and therefore the HMAC secret used to validate `X-Hub-Signature`) purely from attacker-controlled JSON fields in the same request body: [1](#0-0) [2](#0-1) 

Once the signature is accepted, `create` dispatches the entire raw JSON `params` to the registered handlers for the event type, without any further validation that the payload's repository matches the organization whose secret validated the request: [3](#0-2) 

For most events (`push`, `pull_request`, `check_suite`), the handler at least scopes to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`: [4](#0-3) 

But `StatusHandler`, registered for the `status` event, ignores the repository/organization entirely and resolves the target purely by commit SHA across the whole installation: [5](#0-4) [6](#0-5) 

This breaks the trust binding the rules describe: `repository_owner` (used to pick the verifying webhook secret) ≠ the repository whose commit is actually written to (`Commit.where(sha:)` has no `stack`/`repository` filter). If a Shipit deployment is configured with multiple GitHub App organizations in `config/secrets.yml` (a documented, supported configuration — see `github:` map with `somegithuborg`/`someothergithuborg` keys), any entity holding one organization's `webhook_secret` can sign a `status` payload whose `sha` collides with a commit tracked under a *different* organization's stack, and Shipit will accept and apply that status.

The consumed status feeds directly into deploy-gating logic: [7](#0-6) [8](#0-7) 

`create_status_from_github!` updates `statuses`, which recomputes `status`/`success?`/`deployable?`, and `add_status` even schedules merges (`stack.schedule_merges`) when the new status is `success`: [9](#0-8) 

So an attacker who signs a forged `status` webhook with `state: "success"` and a target commit SHA from a victim organization's stack can flip that commit's CI status to green, which can unblock an automatic/continuous deploy or a pending merge for a repository the attacker has no legitimate access to.

### Impact Explanation
This is a cross-repository/cross-organization write that can trigger an unauthorized deploy or merge decision on a stack the attacker does not control — matching the Critical criterion "cross-repository writes, or an unauthorized deploy, rollback or merge." The attacker never needs any Shipit session, API token, or write access to the victim's actual GitHub repository — only a webhook secret belonging to any organization onboarded into the same Shipit instance.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured with more than one GitHub organization (a documented/supported setup shown in `config/secrets.development.shopify.yml`), and (2) knowledge of the SHA of a commit tracked in a victim stack (SHAs are not secret — they're visible in the Shipit UI, GitHub, PR links, etc.), and (3) possession of the webhook secret for *any one* configured organization (not necessarily the victim's). The set of organizations sharing one Shipit deployment is an explicit, supported multi-tenant use case, so this is reachable without any of the excluded privileges (no ApiClient token, no `webhook_secret`/`api_clients_secret` of the *victim* org, no GitHub App private key of the victim, no repository write access, no privileged Shipit account).

### Recommendation
In `StatusHandler#process` (and any other handler that mutates state keyed only by `sha`), scope the lookup to the repository asserted by `verify_signature`/the payload's own `repository.full_name`, e.g. restrict to `stacks.commits.where(sha: params.sha)` instead of the global `Commit.where(sha:)`, and additionally assert in `WebhooksController#verify_signature` that the resolved `github_app`'s organization actually owns the payload's `repository.full_name` before dispatching to any handler.

### Proof of Concept
1. Configure Shipit with two organizations in `config/secrets.yml`, `org-attacker` and `org-victim`, each with its own `webhook_secret` (a supported multi-org deployment, per `config/secrets.development.shopify.yml`).
2. As someone who controls `org-attacker`'s GitHub App (its own webhook secret), locate a tracked commit SHA belonging to a stack under `org-victim` (e.g., from the Shipit dashboard or GitHub PR link).
3. Send `POST /webhooks` with header `X-Github-Event: status`, body `{"sha": "<victim-commit-sha>", "state": "success", "context": "ci/required", "repository": {"owner": {"login": "org-attacker"}}}`, and `X-Hub-Signature` computed with `org-attacker`'s `webhook_secret`.
4. `verify_signature` resolves and validates against `org-attacker`'s secret and succeeds; `StatusHandler#process` executes `Commit.where(sha: params.sha)` and applies the forged `success` status to the victim's commit, regardless of the `repository` field used for signature selection, potentially unblocking a deploy/merge on `org-victim`'s stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
