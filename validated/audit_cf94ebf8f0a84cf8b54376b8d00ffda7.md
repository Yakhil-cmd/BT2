This confirms the exploit chain: forging a commit status can auto-trigger a merge via `add_status`'s call to `stack.schedule_merges` and `MergeRequest#all_status_checks_passed?`, which is then acted upon by `ProcessMergeRequestsJob#perform` to call `merge_request.merge!`, which issues a real GitHub merge using the app's real GitHub credentials.### Title
Cross-repository commit-status forgery via webhook signature scoped to organization while `StatusHandler` writes unscoped by repository - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App configuration for the organization named in the payload's `repository.owner.login` (or `organization.login`) field, then dispatches the entire payload to event handlers. The `status` event handler, `Shipit::Webhooks::Handlers::StatusHandler`, does not scope its lookup to the authenticated repository/organization at all — it matches purely on `Commit.where(sha: params.sha)` across the *whole* Shipit instance. This breaks the trust binding that should exist between "the organization whose secret validated this webhook" and "the repository/commit that gets written."

### Finding Description
In `WebhooksController`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This selects the `GitHubApp` config (and therefore the `webhook_secret` used for HMAC verification) purely by the organization named in the payload — a value fully attacker-controlled if the attacker can submit any signed payload whose `repository.owner.login` matches an organization they legitimately control (i.e., an org where they own the real GitHub App installation and its webhook secret, which they can use to legitimately sign requests for their own org's events).

Once the signature is verified against Org A's secret, the entire event dictionary — including any nested `sha` value — is handed unmodified to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) .

For the `status` event, the dispatched handler is:
```ruby
class StatusHandler < Handler
  params do
    requires :sha, String
    requires :state, String
    ...
  end

  def process
    Commit.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
``` [3](#0-2) 

Unlike other handlers (e.g. `PushHandler`, pull-request handlers) which resolve `stacks`/`repository` via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` (see `Handler#stacks`/`#repository_name`) [4](#0-3) , `StatusHandler#process` performs a **global** `Commit.where(sha: ...)` lookup with no repository/stack scoping whatsoever. The binding that should be enforced — "the org that authenticated == the repository whose commit is written" — is completely absent for this handler.

A commit `sha` is not secret; it's public on GitHub for any repository. Any commit hash on any Shipit-tracked stack (belonging to any organization, including ones the attacker has no push access to) can therefore be targeted by an attacker who legitimately controls a completely unrelated organization's webhook secret.

`Commit#create_status_from_github!` feeds into `Commit#add_status`, whose side effect is:
```ruby
stack.schedule_merges if new_status.pending? || new_status.success?
``` [5](#0-4) 

`schedule_merges` eventually triggers `ProcessMergeRequestsJob#perform`, which checks `merge_request.all_status_checks_passed?` (backed by `StatusChecker.new(head, head.statuses_and_check_runs, ...)`) and, if satisfied, calls `merge_request.merge!` [6](#0-5) [7](#0-6) . `merge!` performs a real GitHub merge using Shipit's own GitHub App credentials: `stack.github_api.merge_pull_request(stack.github_repo_name, number, ...)` [8](#0-7) .

### Impact Explanation
An attacker who controls a legitimate GitHub organization tracked by a shared Shipit instance (and therefore knows/can use that org's real webhook secret through GitHub's normal webhook delivery, or who owns any org configured on the instance) can forge a `success` commit-status webhook for a commit `sha` belonging to an entirely different tracked repository/organization. Because the merge queue relies on `all_status_checks_passed?` to gate `MergeRequest#merge!`, this can cause an unauthorized merge (using Shipit's real `GITHUB_TOKEN`/GitHub App credentials) on a victim repository the attacker has no write access to — matching the Critical impact category "unauthorized deploy, rollback or merge" and involves cross-repository writes.

### Likelihood Explanation
Likelihood is High relative to the trust model: any organization configured in `Shipit.github` (multi-org config supports many independent orgs sharing one Shipit instance, per `docs/setup.md` "Using Multiple Github Applications" section) is fully trusted to author `status` webhooks for *any* commit in the system, not just its own repositories. Any tenant organization on a shared Shipit instance is an effective "unprivileged attacker" relative to other tenants' repositories, and commit SHAs are public GitHub data, trivially obtainable for the target repository.

### Recommendation
Scope `StatusHandler#process` (and any other handler that doesn't already do so) to the repository named in the authenticated payload, e.g., restrict the `Commit.where(sha: params.sha)` lookup to commits belonging to `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`'s stacks, matching the pattern used by `Handler#stacks`. Additionally, `verify_signature` should not just pick a webhook secret by an attacker-controlled organization field — it should ensure the resolved GitHub App/organization actually owns the repository referenced by the payload before any handler is allowed to mutate state for that repository.

### Proof of Concept
1. Shipit instance is configured with multiple GitHub organizations (Org A, Org B) per the documented multi-org config in `docs/setup.md`.
2. Org A is a real, attacker-controlled organization with a legitimately configured GitHub App and known webhook secret (or the attacker triggers a real event from their own repo/org to obtain a validly-signed envelope, since GitHub signs the payload with Org A's secret).
3. Attacker crafts (or replays with modification+re-signing, since they know Org A's `webhook_secret`) a `status` event payload: `{"repository": {"owner": {"login": "OrgA"}}, "sha": "<victim_commit_sha_from_OrgB>", "state": "success", "context": "ci/required"}`, HMAC-signed with Org A's `webhook_secret`.
4. `POST /webhooks` with header `X-Github-Event: status` and the correct `X-Hub-Signature`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, verifies successfully against Org A's own secret [9](#0-8) .
6. `StatusHandler#process` finds the commit belonging to Org B's stack purely by `sha` and creates a `success` status for it [10](#0-9) .
7. If this is the last required status, `stack.schedule_merges` fires, `ProcessMergeRequestsJob` sees `all_status_checks_passed?` true, and calls `merge_request.merge!`, causing an unauthorized merge on Org B's repository using Shipit's real GitHub credentials.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-32)
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
    end
```

**File:** app/models/shipit/merge_request.rb (L164-197)
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

    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
