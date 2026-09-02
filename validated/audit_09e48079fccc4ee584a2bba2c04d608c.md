### Title
Cross-repository commit-status forgery leads to unauthorized merge queue bypass - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `status` webhook handler updates a commit's CI status by looking the commit up **only by its SHA, globally across the entire Shipit installation**, without verifying that the commit belongs to the repository/organization whose webhook secret actually signed the request. Any org/repo configured on the same Shipit instance can therefore forge a "success" status for a commit that lives in a completely different, unrelated stack, causing that stack's merge queue to treat CI as passing and auto-merge a pull request that never had real passing checks.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which HMAC secret) to use for verifying the incoming webhook based on the organization named inside the payload itself: [1](#0-0) [2](#0-1) 

This only proves that *some* organization configured in Shipit signed the request (`repository.owner.login` picks the secret to check against). It does **not** bind the verified organization/repository to the resource the handler is about to mutate.

The `status` event handler then completely ignores the `repository` field and resolves the target purely from a global `sha` lookup: [3](#0-2) 

`Commit.where(sha: params.sha)` is not scoped to the `stack`/`repository` implied by the signing organization. Commit SHAs are not secrets — they are visible to anyone with read access to the target repository (or via GitHub's public API for public repos, or via any collaborator/contributor relationship for private ones) — and are frequently exposed in Shipit's own UI, deploy logs, and API responses to any authenticated Shipit user (`GET /:stack_id/tasks`, task streams, etc. — see `app/controllers/shipit/api/tasks_controller.rb` and stack views which show `until_commit.sha`).

`create_status_from_github!` feeds directly into `Commit#add_status`, which — if the state transitions to `success` — schedules the merge queue: [4](#0-3) 

The merge queue (`ProcessMergeRequestsJob`) then checks `all_status_checks_passed?`, which is computed purely from the stored `Status`/`CheckRun` rows attached to the PR's head commit, with no re-verification against the actual GitHub-reported state: [5](#0-4) [6](#0-5) 

If the checks pass, `MergeRequest#merge!` calls GitHub's merge API using the Shipit app's own installation token: [7](#0-6) 

**Binding broken:** the organization that authenticated the webhook (bound by HMAC signature to `repository.owner.login`) ≠ the repository/stack whose commit is actually mutated (bound only by a global, non-secret SHA match). Before the attacker's request, commit `X` in `stack_B` (owned by `OrgB`) has a real, correctly-verified CI status. After a single forged `status` webhook signed with `OrgA`'s (attacker-controlled or attacker-known) webhook secret, but naming `sha: X` (belonging to `OrgB`'s stack), `commit.create_status_from_github!` records a fabricated `success` status on that commit in `OrgB`'s stack, which can trigger an unauthorized automatic merge in `OrgB`'s merge queue.

### Impact Explanation
This crosses the "unauthorized merge" impact bucket explicitly listed as in-scope: an attacker who only controls (or knows the webhook secret for) one low-trust organization/repository configured on a shared Shipit instance can forge passing CI status for a commit belonging to an unrelated, higher-trust repository, and thereby cause Shipit to merge a pull request there without genuine CI approval. This is a cross-tenant authorization break intrinsic to the engine's own commit-status handler, not a third-party gem defect, misconfiguration, or a scenario requiring a Shipit session/API token — only a valid HMAC signature for *any* org configured on the instance is needed.

### Likelihood Explanation
Multi-organization Shipit deployments are explicitly documented and supported (`docs/setup.md`, `lib/shipit/github_app.rb`), so the precondition (more than one org/webhook secret configured) is a normal, documented deployment shape rather than a hypothetical. Obtaining the target SHA requires only ordinary read access to the victim repository (or public repo visibility) — no secret material about the victim organization is needed. The only capability the attacker needs of their own is the ability to have Shipit process a signed webhook for *an* organization they control/know, which is a much weaker requirement than "privileged access to the victim org."

### Recommendation
Scope `StatusHandler#process` (and any other global-SHA-lookup handler) to commits belonging to a `stack`/`repository` that matches the `repository.full_name`/`repository.owner.login` used to authenticate the specific request, e.g. `stack.commits.where(sha: params.sha)` derived from the same repository object that was cryptographically verified, rejecting the event if the resolved repository does not match.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `OrgA` and `OrgVictim`, each with its own `github.webhook_secret` (per `docs/setup.md` multi-org config).
2. Note (or obtain, e.g. via public GitHub API) the SHA of a commit `X` under review in a stack belonging to `OrgVictim`, currently missing/failing its required CI status context.
3. As an attacker who knows/controls `OrgA`'s webhook secret (e.g., an org admin of `OrgA`, or someone who obtained that org's webhook secret), craft a `status` event payload:
   ```json
   { "sha": "X", "state": "success", "context": "<required-context>",
     "repository": { "owner": { "login": "OrgA" } } }
   ```
4. Sign it with `OrgA`'s webhook secret (`sha1=HMAC(payload, OrgA_secret)`) and POST it to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` succeeds because the secret matches `OrgA`.
6. `StatusHandler#process` finds commit `X` (which is in `OrgVictim`'s stack) purely by `Commit.where(sha: "X")` and records the forged `success` status, with no repository cross-check.
7. If this satisfies `all_status_checks_passed?` for a pending PR in `OrgVictim`'s merge queue, `ProcessMergeRequestsJob` calls `merge_request.merge!`, merging the PR in `OrgVictim`'s repository despite the forged status originating from an unrelated organization's credentials.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-31)
```ruby
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

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
