### Title
Webhook signature verification is scoped to an attacker-chosen organization while status/push handlers act on repositories/commits with no ownership check — organization authenticated ≠ repository written - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub organization's webhook secret to validate a request against purely from attacker-controlled JSON body fields, and `GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatically valid. Several event handlers (most notably `StatusHandler`) then act on data (a commit `sha`) with **no check at all** that it belongs to the organization/repository that was used to authenticate the request. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`verify_signature` derives the organization used for signature checking entirely from the untrusted payload: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` when the resolved organization has no configured `webhook_secret`: [3](#0-2) 

Because the organization used for authentication is chosen by the attacker (`repository.owner.login` / `organization.login` in the body), any organization in `secrets.github` that has no `webhook_secret` configured lets an attacker satisfy `verify_signature` for *any* payload content, regardless of which real repository/stack they intend to target.

Once past `verify_signature`, `StatusHandler` performs zero repository/organization scoping — it matches purely on commit SHA across the entire installation: [4](#0-3) 

This directly parallels the analog smart-contract bug: a value (`ftReserve`, i.e. "the reserve the code trusts") is read/validated in one context but the subsequent state-changing action (`market.mint`, i.e. minting extra `ft`) is performed against a *different*, unchecked, real quantity. Here, the "verified" quantity is *which organization's secret validated the request*, while the "acted upon" quantity is *an arbitrary commit/stack chosen independently by the attacker* — the two are never cross-checked.

`Commit#create_status_from_github!` -> `add_status` will fire `deployable_status` hooks and call `stack.schedule_merges` on a `success` transition: [5](#0-4) 

`schedule_merges` feeds `ProcessMergeRequestsJob`, which merges pull requests once `all_status_checks_passed?` is true: [6](#0-5) 

`PushHandler` and `CheckSuiteHandler` are similarly reachable once *any* configured organization's `verify_signature` step is bypassable, but they at least scope by `repository.full_name` via `Repository.from_github_repo_name`: [7](#0-6) 
`StatusHandler`, however, has no such scoping at all.

### Impact Explanation
An attacker who can get one organization entry in `secrets.github` recognized with a blank/missing `webhook_secret` (a misconfiguration that is silently accepted rather than rejected, per `verify_webhook_signature`'s `return true unless webhook_secret`) can forge a `status` webhook event that is authenticated under that weak organization, but whose `sha` refers to a commit belonging to a completely different, properly-secured stack/repository tracked by the same Shipit instance. This can flip an unrelated commit's CI status to `success`, triggering `stack.schedule_merges`, which can cause `ProcessMergeRequestsJob` to merge pull requests, and can also feed into `continuous_deployment` deploy triggers — an unauthorized merge/deploy action on a repository the attacker never authenticated against. This matches the "Critical: unauthorized deploy, rollback or merge" bar.

### Likelihood Explanation
Likelihood depends on at least one organization in the multi-tenant `secrets.github` configuration lacking a `webhook_secret` (a documented but easy-to-miss per-organization key) — this is an unprivileged-attacker path once that misconfiguration exists, since no session, API token, or repository write access is required; only knowledge of a target commit SHA (learnable from public GitHub activity) is needed.

### Recommendation
- Make `webhook_secret` mandatory per configured organization; fail closed (reject, don't accept) if absent, rather than `return true unless webhook_secret`.
- In `verify_signature`, cross-check that the organization used to select the signing secret actually matches the repository owner referenced by the handler's target data, and reject if there is any inconsistency between `repository.owner.login`/`organization.login` and the resource being mutated.
- Update `StatusHandler` (and any handler lacking it) to scope lookups by the tracked repository/stack derived from the verified organization, not merely by a globally-unique field like commit SHA.

### Proof of Concept
1. Configure two organizations in `secrets.github`: `org-a` (no `webhook_secret`) and `org-b` (properly configured, hosts the real target stack/repo).
2. Attacker learns the SHA of a real, still-pending commit belonging to a stack under `org-b`.
3. Attacker sends a `status` webhook to `WebhooksController#create` with header `X-Github-Event: status`, body `{"sha": "<org-b commit sha>", "state": "success", "repository": {"owner": {"login": "org-a"}}}`.
4. `verify_signature` resolves `Shipit.github(organization: "org-a")`, whose `verify_webhook_signature` returns `true` unconditionally (no secret configured), so the forged request is accepted.
5. `StatusHandler#process` matches `Commit.where(sha: params.sha)` — the `org-b` commit — and calls `commit.create_status_from_github!(params)`, marking it `success` and potentially triggering `stack.schedule_merges` on the `org-b` stack, despite the request never having been authenticated against `org-b`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L366-384)
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
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-31)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
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
