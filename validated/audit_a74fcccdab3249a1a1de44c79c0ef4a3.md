### Title
StatusHandler mutates commit Status for any stack matching `params.sha`, independent of the webhook's authenticated organization - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits globally by `sha` and writes attacker-supplied `state`/`context`/`description`/`target_url` onto whatever `Commit` matches, with no check that the commit's stack/repository belongs to the organization whose webhook secret authenticated the request. Because git commit SHAs are content-derived and identical across forks, an attacker who owns a fork of a victim's public repository (and thus has a legitimately-signed webhook channel for their own org) can push a `status` event whose `sha` matches a shared ancestor commit that also exists in a victim stack, flipping that commit's blocking/required status to `success` and injecting arbitrary `description`/`target_url` strings into the victim stack's UI.

### Finding Description
The intended binding is: `authenticated_org(repository_owner passed to Shipit.github(...).verify_webhook_signature)` == `owner_org(stack of the Commit row being mutated)`. This is never checked.

Code path:
- `WebhooksController#verify_signature` resolves the GitHub App config purely from the attacker-controlled JSON body via `repository_owner = params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) . For a real webhook delivered by GitHub for a repository the attacker legitimately owns/controls (a fork), this signature check passes honestly - the attacker never needs to know any secret, GitHub computes it.
- `StatusHandler#process` then does a completely unscoped lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) . There is no join/filter on stack, repository, or the `repository_owner` that authenticated the request.
- `Commit#create_status_from_github!` forwards straight into `Status.replicate_from_github!`, which persists `state`, `description`, `target_url`, `context` verbatim [3](#0-2) [4](#0-3) .
- `Status` only validates `state` inclusion in `STATES`; `context`, `description`, `target_url` have no format/length/allow-list validation [5](#0-4) .
- `Status::Common#blocking?`/`#required?` key off `context` string matching the victim stack's own configured blocking/required contexts [6](#0-5) , so an attacker who knows (or guesses, since CI context names are typically public, e.g. `ci/travis`) the victim's required context can supply `state: success` for that exact context.

Since git SHAs are a hash of commit content + parent chain, a fork of a public repository shares identical SHAs with the upstream history up to the point of divergence. An attacker who forks the victim's repo, or who owns any repository sharing commit history with the victim (submodule references, vendored history, common upstream, etc.), can trigger a real, validly-signed `status` webhook from GitHub for their own repository that references one of these shared SHAs. `StatusHandler` will apply the attacker's `state`/`context`/`description`/`target_url` to the `Commit` row for that SHA regardless of which stack it actually belongs to, because the lookup is global and the write path never re-verifies `commit.stack.repository`/owner against the org that authenticated the webhook.

None of the existing guards catch this: `verify_signature` only proves the payload came from the org named inside the payload itself, `drop_unhandled_event` only filters unregistered event types, the `ExplicitParameters` schema only type-checks strings, and there is no `Stack`/`Repository` cross-check anywhere in `StatusHandler` or `Commit#create_status_from_github!`.

### Impact Explanation
A successfully forged status write lets an attacker (from a fully unrelated, unprivileged tenant) directly:
- Flip a victim stack's blocking/required CI context to `success`, clearing `Commit#blocked?` and thus `Commit#deployable?` [7](#0-6) , enabling an unauthorized deploy (or making the commit eligible for a rollback target) on a stack the attacker never authenticated for.
- Inject arbitrary `description`/`target_url` strings that render in the victim stack's task/commit UI.

This is a payload for one (attacker-controlled) repository mutating another repository's stack/commit state, matching the "Critical" category (unauthorized deploy/rollback eligibility, cross-tenant record mutation).

### Likelihood Explanation
Preconditions: the attacker needs a repository they control whose commit history shares a SHA with a commit tracked by the target Shipit stack (trivially satisfied by forking any public repo tracked by Shipit, which is the common case for open-source projects using Shipit), and that repository/org must have a working GitHub App/webhook integration into the same Shipit instance (a normal, low-cost setup for any GitHub user integrating their own fork). No Shipit session, API token, or knowledge of any webhook secret is required — GitHub itself computes and sends the valid signature for the attacker's own org. The attack is repeatable against any tracked commit SHA the attacker can reproduce in their own history, and against any context string the attacker can guess or observe.

### Recommendation
In `StatusHandler#process` (and analogously in the CheckRun/other handlers using unscoped `Commit.where(sha:)` lookups), scope the commit lookup to the repository/organization that authenticated the webhook, e.g. join through `Stack`/`Repository` and filter by `repository_owner`/`repository full_name` from the verified payload before calling `create_status_from_github!`. Reject or ignore statuses for commits whose stack's repository does not match the authenticated repository.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb`, no live GitHub required):
1. Create `stack_a` (org "attacker-org/repo") and `stack_b` (org "victim-org/repo"), each with a `Commit` sharing the identical `sha` value "deadbeef...".
2. Configure `stack_b`'s deploy spec/required statuses so that context `"ci/travis"` is a required/blocking status; assert `stack_b.commits.last.deployable?` is `false` before the call.
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call('sha' => shared_sha, 'state' => 'success', 'context' => 'ci/travis', 'description' => 'pwned', 'target_url' => 'https://evil.example', 'repository' => { 'owner' => { 'login' => 'attacker-org' } })` — simulating a webhook that only ever authenticated `attacker-org`.
4. Assert both `stack_a`'s and `stack_b`'s commits now have a `Status` row with `state == 'success'`, `description == 'pwned'`, `target_url == 'https://evil.example'`.
5. Assert `stack_b.commits.last.reload.deployable?` is now `true`, proving a payload that only authenticated `attacker-org` toggled deployability for `victim-org`'s stack — violating the equality `authenticated_org(repository_owner) == owner_org(stack of mutated commit)`.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status.rb (L8-16)
```ruby
    STATES = %w[pending success failure error].freeze
    enum :state, STATES.zip(STATES).to_h

    belongs_to :stack, required: true
    belongs_to :commit, required: true

    deferred_touch commit: :updated_at

    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true
```

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end
```

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```
