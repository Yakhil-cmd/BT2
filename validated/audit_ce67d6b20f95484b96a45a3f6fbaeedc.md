### Title
Cross-repository CI-status forgery via unscoped SHA lookup in `StatusHandler` breaks org-authenticated-vs-repository-written binding - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates a `status` webhook against the GitHub organization derived from the payload's own `repository.owner.login`, but the handler that then *acts* on that payload — `StatusHandler` — never re-checks that the target `Commit` actually belongs to a stack/repository under that authenticated organization. It looks up commits purely by SHA across the entire `commits` table.

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and verifies the HMAC signature using that organization's configured `webhook_secret`: [1](#0-0) 

This establishes the trust binding: *the organization whose secret validated this payload* should be the only organization whose data the payload is allowed to mutate. Every other default handler respects this by scoping lookups through `Handler#stacks`, which filters by `Repository.from_github_repo_name(repository_name)` (i.e., the payload's own `repository.full_name`): [2](#0-1) [3](#0-2) 

`StatusHandler`, however, bypasses this entirely and queries commits globally by SHA with no repository/stack scoping at all: [4](#0-3) 

Because Git commit SHAs are content-addressed (hash of tree, parent, author/committer, message/timestamps) and identical across forks/shared history, any org/repository that is itself onboarded to the Shipit instance (has a valid `webhook_secret`) can legitimately sign a `status` event whose `sha` field matches a commit that exists in a *different*, unrelated stack tracked by Shipit (e.g. a shared ancestor commit from a fork, or a deliberately reproduced identical commit). `StatusHandler#process` will then call `commit.create_status_from_github!(params)` on that unrelated commit, injecting arbitrary CI status data (`state`, `context`, `target_url`, `description`) into the target stack's commit status history: [5](#0-4) 

The binding broken, as an equality: `organization authenticated by webhook signature == organization whose repository/stack is written by the handler`. Before the attack this holds for all default handlers except `StatusHandler`; a `status` webhook signed by organization A can write a status onto a `Commit` belonging to a `Stack` under an unrelated organization B, purely because the SHA matches.

### Impact Explanation
`Commit#create_status_from_github!` feeds directly into `Commit#status`, `Commit#deployable?`, and `Commit#schedule_continuous_delivery`: [6](#0-5) [7](#0-6) 

A forged "success" status for a required CI context can satisfy `stack.ignore_ci?`/CI-required-status checks and, when `stack.continuous_deployment?` is enabled, directly triggers `ContinuousDeliveryJob` for the victim stack — i.e. an unauthorized deploy triggered by an org that was never granted trust over that stack's repository. This matches the Critical-impact category: "an unauthorized deploy... " triggered without the victim organization's authorization.

### Likelihood Explanation
Exploitation requires the attacker to control any organization/repository already configured in the Shipit instance (i.e. capable of sending a validly-signed webhook for their own repo) and to know or reproduce a commit SHA that also exists in the target stack's `commits` table (trivial for public forks/shared histories, or for monorepo/vendored-history scenarios). No repository write access, GitHub App key, or Shipit session is needed — only ordinary control of a legitimately onboarded but low-privilege repository.

### Recommendation
Scope `StatusHandler#process` the same way every other handler is scoped: resolve commits only within `stacks` (i.e. `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) rather than querying `Commit.where(sha: params.sha)` globally, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or restrict to `Commit.joins(:stack).merge(stacks).where(sha: params.sha)`.

### Proof of Concept
1. Attacker controls `attacker-org/some-repo`, onboarded to the target Shipit instance with its own legitimate `webhook_secret`.
2. Attacker forks/replicates a commit that also exists (by identical content/history) in `victim-org/critical-repo`, a stack with `continuous_deployment: true` and a required CI context `ci/required`.
3. Attacker sends a `status` event, correctly HMAC-signed with `attacker-org`'s webhook secret, with `sha` = the shared commit SHA and `state: "success"`, `context: "ci/required"`.
4. `WebhooksController#verify_signature` validates the signature against `attacker-org` and passes.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the commit belonging to `victim-org/critical-repo`'s stack, and calls `create_status_from_github!`, marking the required check as passed.
6. `Commit#schedule_continuous_delivery` fires, enqueuing `ContinuousDeliveryJob` for the victim's stack, resulting in an unauthorized deploy triggered by an attacker who never had write access to `victim-org/critical-repo`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
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
