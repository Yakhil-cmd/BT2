Confirmed: webhook signature verification is per-organization (a single `webhook_secret` shared by every repository in that GitHub org, keyed off `params.dig('repository','owner','login')` in `WebhooksController#verify_signature`), while `StatusHandler#process` performs no repository/stack scoping at all.

### Title
Cross-repository/cross-stack status forgery via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely `Commit.where(sha: params.sha)` [1](#0-0)  without ever verifying that the resolved commit's stack belongs to the repository named in `payload['repository']['full_name']`. Every other handler (e.g. `PushHandler`) scopes results through `Handler#stacks`, which derives the repository from the payload before touching any records [2](#0-1) [3](#0-2) , but `StatusHandler` omits this entirely.

### Finding Description
The broken binding: `stack derivable from payload.repository` should equal `stack whose Status/ContinuousDeliveryJob gets mutated`, but `StatusHandler` never computes the former at all.

Path: `WebhooksController#create` → `Shipit::Webhooks.for_event('status')` → `StatusHandler.call(params)` → `StatusHandler#process` iterates `Commit.where(sha: params.sha)` **across the entire commits table, regardless of stack/repository** [1](#0-0) , then calls `commit.create_status_from_github!(params)` → `statuses.replicate_from_github!` → creates a `Status` row → `after_commit :schedule_continuous_delivery` [4](#0-3)  → `commit.schedule_continuous_delivery`, which enqueues `ContinuousDeliveryJob` if `stack.continuous_deployment?` and `stack.deployable?` [5](#0-4) .

Signature verification (`WebhooksController#verify_signature`) only proves the request came from GitHub for the **organization** named by `repository.owner.login`, using one `webhook_secret` shared by every repository under that org [6](#0-5) [7](#0-6) . It does not, and cannot, prove the event originated from the specific repository whose sha is being referenced. Since `StatusHandler` never checks `repository_name`/`repository_owner` against the commit's stack, any repository within an onboarded organization that can trigger a real `status` webhook (e.g. a low-privilege contributor's own repo, or any repo under that org with CI posting commit statuses) for a sha that coincidentally also exists in another repo's tracked stack under the same org will create a `Status` and can trigger continuous delivery for that unrelated victim stack. Because git commit SHAs are content-addressed, an attacker can reproduce an identical commit object (same tree, parents, author/committer, timestamps, message) from a public victim repository inside their own repository and post a `success` status against that sha via the GitHub Statuses API on their own repo, causing GitHub to emit a legitimately-signed `status` webhook that Shipit will apply to the victim's commit/stack.

None of the existing guards stop this: `verify_signature` only checks organization-level authenticity, not repository identity; `ExplicitParameters` only validates the shape of `sha`/`state`/etc, not their relation to any repository; `Handler#stacks`/`repository_name` exist but are simply never invoked by `StatusHandler`.

### Impact Explanation
A webhook event bound to repository/organization A can create a `Status` for and enqueue a `ContinuousDeliveryJob` against a stack belonging to a different, victim repository B under the same Shipit-managed organization — a "payload for one repository mutating another's stack," explicitly a Critical-severity category. This can cause an unauthorized deploy of the victim stack (if `continuous_deployment` is enabled) and is repeatable against any stack for which a colliding/reproduced sha can be posted.

### Likelihood Explanation
Requires: (1) the attacker to control a repository capable of emitting a genuinely GitHub-signed `status` webhook to the Shipit host (i.e., a repo under an org already onboarded to Shipit, since signature verification is keyed by organization), (2) a commit sha that is shared between the attacker's repo and the victim's tracked commit — achievable deterministically by copying the exact git commit object from a public victim repository into the attacker's own repository, then using the Statuses API against their own repo, (3) the victim stack has `continuous_deployment` enabled for full deploy impact (a `Status` record is created regardless, which is itself a data-integrity violation even without CD). Attacker cost is a single crafted commit and a status API call; no Shipit secret is required beyond the ability to trigger a real, validly-signed webhook for a repo they control within a shared org.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup by the stack(s) resolved from `payload['repository']['full_name']` (reusing `Handler#stacks`), e.g. resolve `stacks.joins(:commits).where(shipit_commits: { sha: params.sha })` or otherwise verify `commit.stack.repository == Repository.from_github_repo_name(repository_name)` before calling `create_status_from_github!`, mirroring what `PushHandler` already does.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
test "status event for one repo does not create a Status on a commit belonging to a different stack/repo" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  victim_stack.update!(continuous_deployment: true)
  attacker_repo_full_name = "shopify/some-other-onboarded-repo"

  shared_sha = "deadbeefcafebabe0000000000000000000000"
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)

  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'branches' => [{ 'name' => 'master' }],
    'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'shopify' } }
  }

  assert_no_enqueued_jobs only: ContinuousDeliveryJob do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end
  assert_equal 0, victim_commit.reload.statuses.count
end
```
Currently this test fails: `StatusHandler.call` creates a `Status` on `victim_commit` and enqueues `ContinuousDeliveryJob` with `args: [victim_stack]` even though `attacker_payload['repository']['full_name']` never names `victim_stack`'s repository, demonstrating the broken binding.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
