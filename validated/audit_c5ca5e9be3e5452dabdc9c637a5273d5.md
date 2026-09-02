Based on my investigation, I found a valid analog to the reported access-control bug class in this codebase.

### Title
Cross-Repository Commit Status Injection via Unscoped SHA Lookup in StatusHandler - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The `status` webhook handler resolves the target `Commit` purely by matching the `sha` field from the GitHub payload, with no scoping to the repository/organization that the webhook signature was actually verified against. This breaks the binding between "the organization whose webhook signature was authenticated" and "the repository/stack whose commit state gets written," allowing an attacker who controls any repository sharing commit history with a tracked stack (e.g. a fork) to inject fabricated CI status into the tracked stack's commit records.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App config to validate the HMAC signature against based on `repository_owner` (`params.dig('repository', 'owner', 'login')`), and only checks that the raw payload bytes match that org's `webhook_secret`. [1](#0-0) 

Once the signature is verified for that specific org/repo, the actual event dispatch does not re-derive or re-check which repository is being mutated. For the `status` event, `StatusHandler#process` looks up commits solely by `sha`, with zero scoping to `repository.full_name` or any stack/org boundary: [2](#0-1) 

`Commit` records are stored per-stack (`belongs_to :stack`), but the query `Commit.where(sha: params.sha)` searches across **all** stacks/repositories in the Shipit instance: [3](#0-2) 

Since Git commit SHAs are computed from tree content and parent SHAs, any two repositories that share history (most commonly a fork and its upstream, but also mirrors, or any repo where an old commit was cherry-picked/rebased) will have literal SHA collisions for shared commits. Because the handler ignores the `repository` field entirely, a webhook whose signature was validly checked against organization/repo **A** can still write a `Status` record onto a `Commit` belonging to stack/repo **B**, as long as both A and B share a commit with the same SHA and both are tracked by the same Shipit instance.

This is the analog of the reported bug: the `SapTestToken.releaseTokens()` function trusted its caller instead of checking that the call actually originated from the authorized `SapienRewards` contract; here, `StatusHandler` trusts the `sha` alone instead of checking that the event actually originates from (and pertains to) the repository whose signature was verified.

### Impact Explanation
Creating a `Status` triggers `Commit#add_status`, which (via `create_status_from_github!`) can flip a commit's simple state to `success`/`pending` and calls `stack.schedule_merges` and schedules `ProcessMergeRequestsJob`/`ContinuousDeliveryJob`: [4](#0-3) [5](#0-4) 

If the shared commit in the victim stack is otherwise pending required CI checks, an attacker-controlled repository (e.g., their own fork, where they have full write access to set arbitrary commit statuses via GitHub's own status API) can cause a forged "success" status to land on the victim stack's commit, potentially satisfying `required_statuses`/`merge_request_required_statuses` and enabling an unauthorized merge (`ProcessMergeRequestsJob` → `MergeRequest#merge!`) or unauthorized continuous deployment (`ContinuousDeliveryJob`) of that commit — matching the "unauthorized deploy, rollback or merge" Critical impact bucket.

### Likelihood Explanation
Exploitation requires: (1) the attacker's own repository (with a legitimately configured GitHub App/webhook, which they control since it's their own repo) to be tracked as a Shipit stack, or their fork's push access, and (2) a shared commit SHA between their repo and a victim stack tracked by the same Shipit instance — a very common situation for forks of open-source projects using shared Shipit instances. No secrets, sessions, or GitHub App private keys need to be compromised; the attacker only needs ordinary push/status-setting rights on a repository whose history overlaps with the target stack.

### Recommendation
Scope the `status` (and any other SHA-keyed) webhook handler lookups by the repository/stack derived from the verified webhook payload, not by `sha` alone, e.g. `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })` using the `Handler#stacks` helper (which already resolves `Repository.from_github_repo_name(repository_name)`), so status updates can only ever apply to commits belonging to the repository that was actually authenticated.

### Proof of Concept
1. Attacker forks a Shopify-tracked repository `Shopify/app` to `attacker/app-fork`, and gets `attacker/app-fork` added as a Shipit stack (Shipit only requires it to be added as a stack; GitHub App installation permissions on a fork are attacker-controlled since it's their own repo).
2. Locate a commit SHA `X` present in both `Shopify/app`'s tracked branch history and `attacker/app-fork` (any shared ancestor commit, extremely common right after forking).
3. Using GitHub's Statuses API on their own fork (`attacker/app-fork`), the attacker sets a `success` status with `context` equal to one of the victim stack's `required_statuses` (e.g. `ci/circleci`) for commit `X`.
4. GitHub sends Shipit a `status` webhook for `attacker/app-fork`; `WebhooksController#verify_signature` validates it correctly against `attacker`'s org's webhook secret.
5. `StatusHandler#process` runs `Commit.where(sha: 'X')`, which also matches the `Shopify/app` stack's `Commit` record for SHA `X`, and creates a forged `success` `Status` on it via `commit.create_status_from_github!(params)`.
6. If that commit in `Shopify/app` was pending required CI, it now appears to have passed, potentially triggering `ProcessMergeRequestsJob` to merge an associated pull request or `ContinuousDeliveryJob` to deploy it.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
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

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
