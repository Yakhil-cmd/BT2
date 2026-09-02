### Title
Webhook signature is verified against an attacker-selectable organization while the `status` event is applied to commits across all repositories - unauthorized cross-repository CI status forgery leading to unauthorized merges/deploys ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App / `webhook_secret` to validate the HMAC signature against using an organization name taken directly from the **unverified** JSON body, then verifies the *entire* raw payload against that secret. Because the signature only proves "this body was signed by the org named in `repository.owner.login`", but `Shipit::Webhooks::Handlers::StatusHandler` (the `status` event handler) never checks which repository/organization a commit status belongs to - it just does `Commit.where(sha: params.sha)` across the whole installation - an attacker who legitimately controls one onboarded GitHub organization (and therefore knows that organization's `webhook_secret`) can forge a `status` webhook that is “authenticated” as their own org but writes a fabricated CI status onto a commit belonging to a completely different organization/repository hosted on the same Shipit instance.

### Finding Description
`verify_signature` derives the signing organization purely from attacker-controlled JSON, not from any pre-verified source: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `GitHubApp` config (and its `webhook_secret`) keyed by that same attacker-supplied string: [3](#0-2) 

Multi-org installations legitimately have distinct `webhook_secret` values per organization (see `test/dummy/config/secrets_double_github_app.yml` and `docs/setup.md`'s "Using Multiple Github Applications" section). Since each org's GitHub App and its `webhook_secret` are set up by whoever administers that org's GitHub App, a tenant who legitimately owns "OrgOne" knows OrgOne's `webhook_secret`.

Once the HMAC check passes (using OrgOne's own secret, computed by the attacker themselves - they craft the whole POST body and its signature), the raw payload is dispatched to handlers based only on the `X-Github-Event` header: [4](#0-3) 

The `status` event handler (`StatusHandler#process`) never scopes to a repository/organization at all - it matches on commit SHA alone, globally: [5](#0-4) 

This differs from other handlers (e.g. `PushHandler`, PR handlers) which derive `repository_name`/`Repository.from_github_repo_name` from `payload.dig('repository','full_name')`: [6](#0-5) 

The binding broken is: **organization authenticated by `verify_signature` (attacker-selected `repository_owner`) ≠ repository/commit actually written by `StatusHandler`**. Before the attack, only GitHub (holding the org-specific secret Shipit itself configured) could produce a valid signature for a given org, and CI statuses only arrive attached to that org's actual commits. After the attack, an attacker holding *any* one org's `webhook_secret` can forge a signature that passes verification for that org, while writing a status onto a commit that belongs to an entirely different stack/repository, because `StatusHandler` performs no ownership check.

The forged status is applied via `Commit#create_status_from_github!` / `add_status`, which can flip deployability and trigger the merge queue: [7](#0-6) 

`schedule_merges` enqueues `ProcessMergeRequestsJob`, which calls `merge_request.merge!` once `all_status_checks_passed?` is true, actually calling GitHub's merge API with Shipit's own credentials for the victim's stack: [8](#0-7) [9](#0-8) 

`Stack#deployable?` also depends on `deployment_checks_passed?`, which is derived from commit status, so a forged "success" status can unlock deploys as well: [10](#0-9) 

### Impact Explanation
An attacker who legitimately administers only one Shipit-onboarded GitHub organization can forge commit statuses for commits belonging to **any other organization/repository** hosted on the same Shipit instance, because signature verification is keyed off an attacker-supplied field while `StatusHandler` performs no per-repository authorization check. This can auto-unlock the merge queue (`ProcessMergeRequestsJob#perform` → `MergeRequest#merge!`), resulting in an unauthorized merge on a repository the attacker does not control, and can also unblock deploys by faking passing CI, satisfying the "unauthorized deploy, rollback or merge" / "cross-repository writes" Critical impact criteria.

### Likelihood Explanation
Requires the attacker to be a legitimate (if low-privilege from Shipit's perspective) administrator of at least one GitHub organization onboarded into a multi-tenant Shipit deployment (i.e., they know that org's `webhook_secret`, which they typically set themselves when creating their org's GitHub App per `docs/setup.md`). They also need to know or guess a target commit SHA in the victim stack (commit SHAs are often disclosed publicly on GitHub, in PRs, or in public repos). No Shipit `ApiClient` token, session, or GitHub App private key is required - only the HTTP endpoint `/webhooks` and their own org's webhook secret.

### Recommendation
Do not select the verification secret from unauthenticated payload content. Either:
- Verify the signature against every configured organization's secret and only accept the payload if the resulting authenticated organization matches the repository/organization actually referenced by the event's `repository.full_name`, or
- Have `StatusHandler` (and any other handler that doesn't already do so) resolve the target commit strictly within the boundary of the organization that successfully signed the request, rejecting statuses for commits/stacks whose repository owner doesn't match the authenticated organization.

### Proof of Concept
1. Attacker legitimately administers `OrgOne`, which is one of several organizations configured under `secrets.github` in a multi-tenant Shipit instance (per `docs/setup.md`), and thus knows OrgOne's `webhook_secret`.
2. Attacker crafts a JSON body for the `status` event:
```json
{
  "repository": { "owner": { "login": "OrgOne" } },
  "sha": "<victim commit sha belonging to OrgTwo's stack>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(OrgOne_webhook_secret, body)` themselves (they know the secret) and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` computes `repository_owner = "OrgOne"`, loads OrgOne's `GitHubApp`, and the HMAC check passes because the attacker generated it correctly.
5. `Shipit::Webhooks::Handlers::StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the victim commit belonging to `OrgTwo`'s stack (no ownership check), calling `commit.create_status_from_github!(params)`.
6. The forged "success" status can trigger `stack.schedule_merges`, enqueuing `ProcessMergeRequestsJob`, which - once other conditions are met - calls `MergeRequest#merge!`, performing a real merge on OrgTwo's repository via Shipit's own GitHub credentials, entirely outside OrgOne's authorization scope.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L19-26)
```ruby
      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
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

**File:** app/models/shipit/stack.rb (L376-382)
```ruby
    def deployable?
      !locked? && !active_task? && !awaiting_provision? && deployment_checks_passed?
    end

    def allows_merges?
      merge_queue_enabled? && !locked? && merge_status == 'success'
    end
```
