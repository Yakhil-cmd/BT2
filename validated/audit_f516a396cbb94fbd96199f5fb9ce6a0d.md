### Title
Cross-repository CI status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` enables unauthorized merges - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits purely by SHA, with no check that the commit belongs to the repository/organization whose webhook signature was verified. This breaks the binding "organization that authenticated versus the repository that is written": an attacker who legitimately controls one Shipit-onboarded organization can forge a `status` webhook, correctly signed with *their own* webhook secret, naming the SHA of a commit that belongs to a *different* stack/repository, and inject a fabricated CI status onto that victim commit. Since CI status directly gates Shipit's automatic pull-request merging (`MergeRequest#all_status_checks_passed?` → `ProcessMergeRequestsJob` → `MergeRequest#merge!`), this can be used to force an unauthorized merge on a repository the attacker has no access to.

### Finding Description
Incoming webhooks are authenticated per-organization: `WebhooksController#verify_signature` selects the verification secret using `repository_owner`, which is read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), and only checks the HMAC signature against that org's `webhook_secret`. [1](#0-0) 

Every other handler in the base `Handler` class scopes its work to the repository named in the same payload via `repository_name`/`stacks`: [2](#0-1) 

`StatusHandler`, however, does not use that scoping at all. It resolves target commits solely by SHA, globally across the entire Shipit instance: [3](#0-2) 

The result: the "organization" whose credentials were verified (the attacker's own onboarded org) is never checked against the repository/stack that the `Commit` row actually belongs to. Any org configured in Shipit (even a low-value test/sandbox org an attacker fully controls) can send a signed `status` event naming a commit SHA from a completely different, victim repository (SHAs of public commits are trivially obtainable from GitHub), and `commit.create_status_from_github!(params)` will write a `Status` record scoped to that commit's real `stack_id` — not the attacker's stack.

Created statuses feed directly into merge-queue automation: `Status#state` changes trigger `schedule_continuous_delivery`, and `MergeRequest#all_status_checks_passed?`/`#any_status_checks_failed?` are computed from `head.statuses_and_check_runs`, i.e., exactly the `Status` rows this handler creates. `ProcessMergeRequestsJob` merges any pending PR once `all_status_checks_passed?` is true: [4](#0-3) [5](#0-4) 

### Impact Explanation
By forging a `success` status for a required CI context on a victim commit, an attacker who controls only their own onboarded organization can cause Shipit to consider an unrelated repository's pull request as passing all checks, triggering `MergeRequest#merge!`, which calls `stack.github_api.merge_pull_request(...)` using Shipit's own privileged GitHub credentials for that victim stack. This is an unauthorized merge performed with the application's GitHub token against a repository the attacker never had write access to — matching the Critical-impact category "an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Exploitation requires only: (1) the attacker controls (or self-service onboards) any organization/repository already configured in the same multi-tenant Shipit instance, so they can legitimately obtain that org's webhook secret or trigger a real webhook from their own repo, and (2) knowledge of a target commit SHA in the victim repository, which is public information for any public GitHub repository and often guessable/observable via the victim's own Shipit UI. No privileged Shipit account, `ApiClient` token, or GitHub write access to the victim repo is needed — only participation as an unprivileged tenant of the same Shipit deployment.

### Recommendation
`StatusHandler#process` must scope commit lookup to the repository named in the payload, mirroring the base `Handler#stacks` pattern used by other handlers, e.g.:
```ruby
def process
  stacks.flat_map(&:commits).where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or otherwise verify that `commit.stack.repository` matches `Repository.from_github_repo_name(repository_name)` before writing the status, so a webhook authenticated for organization A can never mutate CI state belonging to organization B's commits.

### Proof of Concept
1. Attacker owns/administers `attacker-org/attacker-repo`, which is legitimately onboarded as a Shipit stack (so `Shipit.github(organization: 'attacker-org')` has a real, attacker-known `webhook_secret`).
2. Attacker identifies a commit SHA `S` on the victim's public repository `victim-org/victim-repo`, which has an open pull request awaiting a required CI context (e.g. `ci/travis`) to reach `success` before Shipit auto-merges it.
3. Attacker crafts a `status` event payload:
```json
{
  "sha": "S",
  "state": "success",
  "context": "ci/travis",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/attacker-repo" }
}
```
4. Attacker signs the raw body with `attacker-org`'s known `webhook_secret` and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` verifies successfully against `attacker-org`'s secret. `StatusHandler#process` runs `Commit.where(sha: "S")`, finds the victim's commit (regardless of the `repository` field in the forged payload), and calls `commit.create_status_from_github!(params)`, creating a `success` `Status` scoped to the victim's stack.
6. If this satisfies `MergeRequest#all_status_checks_passed?` for the pending victim PR, `ProcessMergeRequestsJob` calls `merge_request.merge!`, causing Shipit to merge the victim's pull request using its own GitHub credentials — an unauthorized merge the attacker could never have performed directly.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L19-31)
```ruby
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
