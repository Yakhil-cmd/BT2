This confirms the strongest candidate finding: the `StatusHandler` is even more severe since it matches by `sha` alone across the whole database, with no `repository`/`stack` scoping at all, and it directly feeds `Status.create_status_from_github!` which can flip a commit's CI state and trigger `ProcessMergeRequestsJob` → `MergeRequest#merge!`, an actual GitHub merge call.### Title
Webhook signature verification org is decoupled from the repository/commit acted on, allowing cross-repository status/merge forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to check the HMAC against using `repository_owner`, a field taken from the *same* untrusted JSON payload (`repository.owner.login` or `organization.login`), but the event handlers that actually mutate state (`Shipit::Webhooks::Handlers::StatusHandler`, `PushHandler`, and the `PullRequest` handlers) key their side effects off *other, independently-controlled* fields of that same payload (`sha` alone, or `repository.full_name`) without cross-checking them against the org whose secret validated the request. This breaks the intended binding "the organization whose secret authenticated the request == the repository being written to," letting anyone who knows one org's `webhook_secret` (a credential Shipit scopes to that org's own repositories per the multi-org configuration documented in `docs/setup.md`) forge events that mutate commits/stacks belonging to a **different** organization's repository on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` computes the verifying `GitHubApp` from the payload itself: [1](#0-0) [2](#0-1) 

This means the "authenticating identity" for a webhook is entirely attacker-supplied JSON (`repository.owner.login`), used solely to look up which `webhook_secret` to HMAC-verify with. Multi-org Shipit deployments configure a distinct `webhook_secret` per GitHub organization, explicitly documented as a boundary between orgs: [3](#0-2) 

Once the signature check passes (using OrgA's secret because `repository.owner.login == "OrgA"`), the raw parsed payload is dispatched unmodified to handlers: [4](#0-3) 

Handlers pick their own scoping fields from that same payload, independent of the org used for signing:
- `StatusHandler` scopes purely by commit `sha` across the **entire database**, with no repository/stack filter at all: [5](#0-4) 
- `PushHandler`, and the `PullRequest::*` handlers, resolve the target `Repository`/`Stack` via `repository.full_name`, a separate JSON field that is never checked against `repository.owner.login`: [6](#0-5) [7](#0-6) 

The equality that should hold is: `org whose webhook_secret verified the raw payload == org that owns the repository/commit being mutated`. In this design the left side is derived from `repository.owner.login`, and the right side is derived from `repository.full_name` (for push/PR handlers) or is not constrained to any org at all (for `StatusHandler`, which only matches on `sha`). An attacker who controls (or has legitimately been given) OrgA's `webhook_secret`—a credential Shipit's own documentation scopes "only" to OrgA's repos—can therefore send a directly-POSTed, correctly-HMAC-signed `status` or `push` event whose `repository.full_name`/`sha` values reference a repository/commit belonging to a completely different organization tracked by the same Shipit instance.

For `status` events specifically, this is exploitable without even needing to guess the victim repo's `full_name`, since matching is purely by SHA: any commit SHA colliding across any tracked repo (which can be brute-forced/guessed or is often known publicly, e.g. via GitHub's public commit API) is a candidate for state injection.

### Impact Explanation
A forged `status` event lets an attacker call `Commit#create_status_from_github!`, which creates a `Status` and can flip a commit's CI state to `success`: [8](#0-7) 
This directly feeds `Commit#schedule_continuous_delivery` (via `after_commit`) and enqueues `ProcessMergeRequestsJob`: [9](#0-8) 
which, once merge requests observe passing checks, calls GitHub's merge API on the target repository using Shipit's own GitHub App/installation credentials: [10](#0-9) [11](#0-10) 

This is an unauthorized merge/deploy gate bypass on a repository/organization the attacker's own webhook credential is not supposed to reach — a cross-repository, unauthorized-merge outcome that meets the "unauthorized deploy, rollback or merge" / "cross-repository writes" bar.

### Likelihood Explanation
Low-to-medium. It requires the attacker to already hold a valid `webhook_secret` for at least one organization onboarded to a multi-org Shipit instance (a legitimate but narrowly-scoped credential per the docs), and (for push/PR handlers) knowledge of the target org/repo's `full_name`, or (for `status`) a matching commit SHA in the victim stack. This is realistic in shared/multi-tenant Shipit deployments where different teams/orgs each hold their own app's webhook secret but expect isolation from each other's repositories — exactly the isolation the docs claim ("A Github application can only authenticate to the Github organization it's installed in").

### Recommendation
Bind the verified signing organization to the resource the handler is allowed to mutate:
- In `WebhooksController`, after `verify_signature`, pass along (or re-verify) that `params.dig('repository','full_name')`'s owner matches the org whose secret validated the signature before dispatching to handlers.
- In `Handler#stacks`/`repository_name`, and specifically in `StatusHandler`, scope lookups by the verified organization (not solely `sha`), e.g. `Commit.joins(stack: :repository).where(sha: params.sha, repositories: { owner: verified_organization })`.
- Reject events where `repository.owner.login` (or `organization.login`) does not match `repository.full_name`'s owner segment.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications" section) and each with at least one tracked `Stack`.
2. As an attacker who legitimately possesses `OrgA`'s `webhook_secret` (e.g., an org owner of `OrgA`'s installed GitHub App), craft a `status` event body:
   ```json
   {
     "sha": "<sha of a commit on OrgB's tracked stack>",
     "state": "success",
     "context": "ci/forced",
     "repository": { "owner": { "login": "OrgA" } }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, raw_body)>` and POST directly to `/webhooks` with header `X-Github-Event: status`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")` and successfully verifies the signature.
5. `Shipit::Webhooks::Handlers::StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the commit belonging to `OrgB`'s stack (no org filtering), and calls `create_status_from_github!`, injecting a `success` status.
6. If `OrgB`'s stack has a pending merge request depending on that commit's CI state, `ProcessMergeRequestsJob` later merges it on GitHub using Shipit's `OrgB` GitHub App credentials — an unauthorized merge triggered entirely by an `OrgA`-scoped credential.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/status.rb (L18-22)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

```

**File:** app/models/shipit/commit.rb (L24-25)
```ruby
    after_commit :schedule_refresh_statuses!, :schedule_refresh_check_runs!, :schedule_fetch_stats!,
                 :schedule_continuous_delivery, on: :create
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

**File:** app/models/shipit/merge_request.rb (L164-185)
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
```
