This confirms a concrete, exploitable analog. Let me verify the `status_handler.rb` field mapping to confirm `sha`/`branches` used for creating statuses come independent of the `repository_owner` used for signature verification.## Title
Webhook signature verification is bound to an attacker-controlled organization while the acted-upon repository is read from an unverified payload field, allowing cross-repository forgery of statuses/pushes/merges - (File: `app/controllers/shipit/webhooks_controller.rb`)

## Summary
`WebhooksController#verify_signature` picks which GitHub App (and therefore which HMAC webhook secret) to validate a request against based on `repository_owner`, a value read directly out of the unauthenticated JSON body. Every webhook handler, however, resolves the *target* repository/stack from a different payload field, `repository.full_name` (or `params.repository.full_name`), which is never cross-checked against the value used to select the verifying secret. In a multi-organization Shipit deployment, an actor who legitimately controls the webhook secret for *their own* onboarded organization can forge a signature that Shipit accepts, while placing an arbitrary `repository.full_name` belonging to a *different* organization's stack inside the same payload. Shipit will treat the signature as proof of authenticity for whatever repository is later referenced, breaking the binding "organization whose secret produced the signature" == "repository the payload is allowed to write to".

## Finding Description
`verify_signature` derives the verifying organization purely from body content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization app configuration/secrets, confirming Shipit explicitly supports separate webhook secrets per org and that `organization` is only a config lookup key, not itself authenticated against repository ownership: [3](#0-2) 
The multi-org secrets layout (`config/secrets.*.yml`, `docs/setup.md` "Using Multiple Github Applications") shows each org has its own independently issued `webhook_secret`, i.e., an organization owner/admin who sets up their own GitHub App entry knows their own org's secret.

Once the signature check passes, the raw JSON body is dispatched to handlers, and `create` never re-validates that the org used for the signature matches the repository named in the payload: [4](#0-3) 

Every handler resolves its target purely from `repository.full_name` in the same untrusted payload, with no linkage back to `repository_owner`: [5](#0-4) 
`PushHandler` uses this to trigger a GitHub sync against arbitrary tracked stacks: [6](#0-5) 
Pull-request handlers similarly resolve `repository` independently and can archive/unarchive review stacks or update `PullRequest` records for any repo Shipit tracks: [7](#0-6) 

Commit statuses created via the `status` webhook feed directly into the merge queue's gating logic. `Commit#add_status` schedules merges whenever a new status becomes `success`/`pending`, and `MergeRequest#all_status_checks_passed?`/`#merge!` decide whether Shipit calls the GitHub merge API: [8](#0-7) [9](#0-8) [10](#0-9) 

Because the signature check and the target-repository resolution use two different, uncorrelated fields of the same attacker-supplied JSON, an org that successfully authenticates a webhook (using its own legitimately-configured secret) can cause Shipit to act on a completely different, unrelated tracked repository.

## Impact Explanation
This breaks the equality: *organization whose webhook secret validated the request* == *repository the payload is permitted to write to*. Concretely, an attacker who controls (or is the legitimate admin of) `OrgA`'s GitHub App entry in a multi-org Shipit deployment can sign a `status` (or `push`, `check_suite`, `pull_request`) webhook body with `repository.owner.login: "OrgA"` (satisfying `verify_signature`) but `repository.full_name: "OrgB/target-repo"` (the field every handler actually acts on). This lets the attacker:
- Forge a `success` commit status for a commit in `OrgB`'s stack, which can trigger `stack.schedule_merges` and ultimately cause Shipit to call `merge_pull_request` on `OrgB`'s repository via `MergeRequest#merge!` — an **unauthorized merge**.
- Trigger `GithubSyncJob`/repository sync or archive/unarchive review stacks for `OrgB`'s repository via `push`/`pull_request` handlers, corrupting deploy state for a stack the attacker has no legitimate relationship to.

This matches the report's "Access Control" bug class: a verification step (signature check) is bound to the wrong entity (the org named in one payload field) while the entity actually acted upon (the repository named in a different, uncorrelated field) is not covered by that verification, allowing an attacker to influence state belonging to a repository/org they don't control.

## Likelihood Explanation
Requires: (1) the deployment uses the documented multi-organization GitHub App configuration (explicitly supported and documented in `docs/setup.md`), and (2) the attacker controls webhook-secret material for at least one onboarded organization while a second, unrelated organization is also tracked by the same Shipit instance. This is a realistic operating model for shared/central Shipit instances serving multiple teams/orgs, since each org's admin who wires up their GitHub App knows their own webhook secret. No GitHub-side compromise of the target org is needed.

## Recommendation
After parsing the payload, verify that the organization/repository owner used to select the verifying webhook secret is exactly the owner of `repository.full_name` (or `organization.login`) actually processed by the handlers, and reject the request otherwise. Do not allow `verify_signature`'s org-selection field and the handlers' repository-resolution field to diverge; ideally, pass the already-verified `repository_owner` into `Webhooks.for_event` handlers and have them assert equality with any repository/org fields they read.

## Proof of Concept
1. Deploy Shipit with the multi-org GitHub App config (`github: { OrgA: {...}, OrgB: {...} }`), each org's admin providing their own `webhook_secret`, and stacks tracked for both `OrgA/*` and `OrgB/target-repo`.
2. As the admin/owner of `OrgA` (who knows `OrgA`'s `webhook_secret`), craft a `status` event JSON body:
   ```json
   {
     "sha": "<commit sha of OrgB/target-repo's open PR head>",
     "state": "success",
     "context": "ci/attacker-forged",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
   }
   ```
3. Sign the raw body with `OrgA`'s webhook secret and set `X-Hub-Signature`; `WebhooksController#verify_signature` looks up `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and validates successfully.
4. `Shipit::Webhooks.for_event('status').each { |h| h.call(params) }` runs the status handler, which resolves the target commit/stack via `repository.full_name` = `"OrgB/target-repo"`, creating a forged `success` status on `OrgB`'s commit.
5. `Commit#add_status` calls `stack.schedule_merges`, and `ProcessMergeRequestsJob`/`MergeRequest#merge!` can subsequently merge a pull request in `OrgB/target-repo` that the attacker never had write access to — an unauthorized cross-repository merge triggered entirely from `OrgA`'s legitimately-signed webhook.

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-59)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L1-34)
```ruby
# frozen_string_literal: true

module Shipit
  class ProcessMergeRequestsJob < BackgroundJob
    include BackgroundJob::Unique
    on_duplicate :drop

    queue_as :default

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
  end
end
```
