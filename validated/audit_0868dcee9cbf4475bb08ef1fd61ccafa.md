### Title
Cross-repository status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits purely by `Commit.where(sha: params.sha)`, with no constraint tying the lookup to the repository that authenticated the webhook. Any onboarded repository/organization can therefore push a forged `state`/`sha` pair that mutates the `statuses` of a `Commit` row belonging to an unrelated stack whose GitHub commit happens to share that SHA, changing that commit's aggregate `status.state`/`success?`/`deployable?` without ever authenticating as that stack's repository.

### Finding Description
The broken binding, stated explicitly: the authenticating repository (`params.dig('repository','owner','login')`, checked in `WebhooksController#verify_signature`) must equal the repository of the `Commit` row being mutated by `StatusHandler#process`. This binding is violated because the handler never reads or compares `params['repository']['full_name']`/`commit.github_repo_name` against anything — it is looked up in `app/controllers/shipit/webhooks_controller.rb:59-62` only for signature-domain selection, and is never passed to or checked inside the handler.

Path:
- `WebhooksController#create` parses the raw JSON body and dispatches to handlers matched by event type only. [1](#0-0) 
- `verify_signature` validates the HMAC using the GitHub App config keyed by `repository_owner` derived from the payload itself, i.e. it proves the payload was signed by *some* configured org's webhook secret, and that org is whatever `repository.owner.login` claims to be — it does not restrict which `Commit`/`Stack` rows the payload's `sha` may subsequently touch. [2](#0-1) 
- `StatusHandler#process` then does a global, unscoped lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. There is no `stack_id`, `repository`, or `github_repo_name` filter. [3](#0-2) 
- `Commit#create_status_from_github!` unconditionally appends the forged status (`add_status` → `statuses.replicate_from_github!`) and recomputes `status`, `success?`, `deployable?`. [4](#0-3) 
- `deployable?` and the `success?`/`state` delegation to `status` directly read the just-mutated aggregate: `delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status` and `deployable? = !locked? && (stack.ignore_ci? || (success? && !blocked?))`. [5](#0-4) 
- By contrast, `create_release_status!` is explicitly gated: `return unless stack.release_status?`, so a forged status cannot *directly* write a `ReleaseStatus` row, but it does change the value any release-gate that reads `deployable?`/`success?` for that shared-SHA commit will observe. [6](#0-5) 

Exploit flow: attacker owns/administers a repository that has already been onboarded as a Shipit stack in the same installation (satisfying "emit webhooks from a repository they own" in the attacker model — this is the normal, unprivileged way to add a `Stack`). Because `sha` and `state` are attacker-controlled JSON fields in the webhook body, not values Shipit fetches independently from GitHub's API, the attacker can set `sha` to the exact (public) SHA of a commit that also exists as a separate `Commit` row under `victim`'s stack (this occurs naturally whenever the same upstream commit is tracked by two different `Stack` records — e.g. two environments/branches of the same repo, or a shared/forked history) and sign the request with their own repo's legitimate webhook secret. `verify_signature` passes because the signature is valid for the attacker's own organization; `drop_unhandled_event` passes because `status` is a handled event; nothing checks that the resulting `Commit.where(sha:)` matches only commits under the attacker's own repository.

### Impact Explanation
The attacker can write a `Status` row (and, by extension, flip `success?`/`deployable?`) for a `Commit` belonging to `victim`'s stack, purely from a webhook their own repository authenticated — this is a payload for one repository mutating another's commit/stack state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Any downstream logic that gates a release/deploy decision on `commit.deployable?`/`success?`/`status.state` for that shared SHA (e.g. continuous delivery scheduling via `schedule_continuous_delivery`, or release checks reading `stack.release_status?` combined with commit success) is influenced without the victim's repository ever authenticating that change. This is repeatable against any commit SHA the attacker can discover (trivial for public repos) as long as a matching `Commit` row exists under another stack in the same Shipit install.

### Likelihood Explanation
Preconditions: attacker needs a repository already registered as a Shipit stack in the same installation (own webhook secret), which is a normal, low-privilege onboarding action, not a Shipit operator/maintainer role. They also need a target `Commit` row with a colliding `sha` under `victim`'s stack, which naturally arises in multi-stack/multi-environment or shared-history setups. No secrets, no GitHub App keys, no session are required — only the attacker's own legitimately-configured webhook secret for their own org. Cost is a single crafted HTTP POST to `/webhooks` with a JSON body; fully repeatable and scriptable.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and analogous handlers such as check-run handling) to commits belonging to a stack whose tracked repository matches `params['repository']['full_name']`/`repository_owner`, e.g. `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: matching_repository.id })`, so a webhook can only mutate commits under the repository that authenticated it.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (proof plan)
test "status webhook from attacker's repo mutates victim's unrelated stack commit" do
  attacker_stack = shipit_stacks(:shipit)          # repo owned/authenticated by attacker's webhook secret
  victim_stack   = shipit_stacks(:shipit2)         # unrelated stack, different repository

  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "victim commit")
  assert_not victim_commit.success?

  params = Shipit::Webhooks::Handlers::StatusHandler.params_class.new(
    sha: shared_sha, state: "success", context: "ci/forged"
  )

  # Signature verified only against attacker's own org secret in WebhooksController#verify_signature;
  # process() never checks repository ownership of matched commits.
  Shipit::Webhooks::Handlers::StatusHandler.new.process # invoked with attacker-signed payload targeting shared_sha

  victim_commit.reload
  assert victim_commit.success?          # binding violated: victim's commit mutated by attacker's authenticated webhook
  assert victim_commit.deployable?       # downstream release-gate signal flipped without victim's repo authenticating it
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L202-213)
```ruby
    def create_release_status!(state, user: nil, target_url: nil, description: nil)
      return unless stack.release_status?

      @last_release_status = nil
      release_statuses.create!(
        stack:,
        user:,
        state:,
        target_url:,
        description:
      )
    end
```

**File:** app/models/shipit/commit.rb (L219-229)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
