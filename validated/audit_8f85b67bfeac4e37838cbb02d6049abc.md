## Title
Cross-repository forgery of commit statuses via unscoped `sha` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
Shipit's webhook signature verification binds a request to the **organization inferred from the payload's `repository.owner.login`** (or `organization.login`), but the `status` event handler that actually mutates state never re-checks that binding: it looks up commits **globally by SHA across every repository/stack in the installation** and appends a GitHub-style status to whatever it finds. This is the same class of bug as the reported Limo issue — a credential/authorization check exists at one layer (permission account ↔ order, here: webhook signature ↔ repository owner) but the privileged action executed at another layer (token transfer, here: commit-status write and the merge/deploy automation it triggers) is never bound to that same identity.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization strictly from attacker-controlled payload fields and validates the HMAC signature against that organization's `webhook_secret`: [1](#0-0) 

The equality the platform intends to enforce is:
`organization whose secret signed the payload == organization/repository whose data the handler is allowed to mutate.`

Every other event handler respects this by scoping lookups through `Handler#stacks`, which resolves `Repository.from_github_repo_name(repository_name)` from `payload.dig('repository','full_name')`: [2](#0-1) 

`StatusHandler`, however, breaks this binding. Its parameter contract requires only `sha` and `state` — no `repository` field at all — and it resolves the target commit with an **unscoped, instance-wide** query: [3](#0-2) 

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

So the request is authenticated as "signed by organization A" (because `repository.owner.login` in the payload says A), but the write is applied to **any** `Commit` record in the database whose `sha` matches — regardless of which stack, repository, or organization that commit actually belongs to. An attacker who controls (or can forge deliveries for) a webhook-enabled repository under organization A can submit a `status` payload naming a SHA that belongs to a commit tracked under an unrelated stack/organization B, and Shipit will happily attach a fabricated `success`/`failure` status to that unrelated commit.

### Impact Explanation
Attaching a forged status is not inert: `Commit#add_status` reacts to state transitions by calling `stack.schedule_merges` on success/pending transitions, and stacks with `continuous_deployment` enabled advance their deploy pipeline based on commit status/state: [4](#0-3) [5](#0-4) 

Merge-queue processing (`ProcessMergeRequestsJob`) merges pending merge requests once `all_status_checks_passed?`, and continuous-delivery logic (`Deploy#schedule_continuous_delivery`, `Stack#trigger_continuous_delivery`) triggers deploys once required statuses turn `success`: [6](#0-5) [7](#0-6) 

Because the SHA lookup crosses repository/organization boundaries, an attacker who only controls webhook delivery for their own (unrelated) repository can forge a `success` CI status on a commit belonging to a victim's stack in a completely different repository/organization, causing that victim stack to auto-merge or auto-deploy a commit whose real CI checks never passed — an unauthorized deploy/merge triggered from outside the victim repository's trust boundary.

### Likelihood Explanation
Exploitation requires: (1) control of a webhook-signing capability for *some* repository/organization configured in the Shipit instance (achievable by anyone who can push to or configure webhooks on any onboarded repo, not necessarily the victim's), and (2) knowledge of the victim commit's SHA, which is routinely public (GitHub commit pages, PR diffs, CI logs) for the vast majority of tracked repositories. No special privilege on the victim stack/repository is needed, matching the "unprivileged attacker breaks a deployment-trust binding" pattern called out in the rules. This is a straightforward, deterministic exploitation path once a SHA is known — no race conditions or guessing beyond obtaining a public commit SHA.

### Recommendation
Require and validate a `repository` field in `StatusHandler`'s parameter contract, and scope the commit lookup exactly as other handlers do (via `stacks`/`Repository.from_github_repo_name`) so that only commits belonging to the repository named in the *same signed payload* used for signature verification can be updated, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
  end
end
```

### Proof of Concept
1. Attacker owns/administers repository `attacker-org/decoy`, which has a Shipit webhook configured with its own (known-to-attacker) `webhook_secret`.
2. Attacker learns the SHA of a commit `abc123...` that is tracked by victim stack `victim-org/prod` (public GitHub data).
3. Attacker crafts a `status` event payload: `{ "sha": "abc123...", "state": "success", "context": "ci/tests", "repository": { "owner": {"login": "attacker-org"}, "full_name": "attacker-org/decoy" } }` and signs it with `attacker-org`'s webhook secret, sending it to Shipit's `/webhooks` endpoint with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` succeeds (correct signature for `attacker-org`).
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, matches the commit under `victim-org/prod`, and calls `create_status_from_github!`, injecting a forged `success` status.
6. If `victim-org/prod`'s merge queue or continuous-deployment is waiting on that status/commit, `Commit#add_status` → `stack.schedule_merges` / continuous-delivery logic proceeds to merge or deploy based on the forged status.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
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
      end
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

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/stack.rb (L231-233)
```ruby
    def schedule_merges
      ProcessMergeRequestsJob.perform_later(self)
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
