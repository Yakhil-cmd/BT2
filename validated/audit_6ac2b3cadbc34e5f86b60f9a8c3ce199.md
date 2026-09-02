Found it: `StatusHandler` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) resolves target `Commit` records by **global SHA lookup** (`Commit.where(sha: params.sha)`), with no scoping to the repository/organization whose webhook signature was actually verified.

### Title
Cross-repository commit-status forgery via unscoped SHA lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) verifies the HMAC signature using the GitHub App configuration bound to `repository_owner` — i.e. `params.dig('repository','owner','login')`. This binds trust to "the organization whose secret signed this payload." However, `StatusHandler#process` never re-checks that binding: it looks up commits purely by `sha` across the entire `Commit` table, then calls `commit.create_status_from_github!(params)` — independent of which repository/organization the verified signature belonged to.

### Finding Description
The equality the engine is supposed to enforce is: `organization whose webhook_secret verified the signature == organization owning the repository whose commits are mutated`. `verify_signature` only checks the signature against `Shipit.github(organization: repository_owner)` using the `repository.owner.login` field from the *same* payload used later by the handler — so far consistent for the *declared* repository. But `StatusHandler` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) discards the `repository` context entirely and matches `Commit.where(sha: params.sha)`, which can span **any** repository/stack tracked by the Shipit instance, since git SHAs are simply 40-hex strings with no cryptographic tie to a specific repo/org.

Any organization/repo that is onboarded to this Shipit instance (has a `Shipit.github(organization: ...)` config and can trigger a legitimately signed `status` webhook, e.g. because it owns *any* repo, even an unrelated toy repo) can craft a `status` event body naming an `after`/`sha` value that collides with a real commit SHA belonging to a different, more privileged stack (e.g. by pushing an identical commit — same tree/parents/message/timestamps produce an identical SHA — a controllable, not-a-hash-preimage-attack scenario since git allows crafting a commit with an arbitrary intended SHA by controlling commit metadata and, for short lookups, `Commit.by_sha` prefix matching used elsewhere). Because `StatusHandler` never filters by `payload.dig('repository','full_name')` (unlike `PushHandler`, which correctly scopes via `stacks` → `Repository.from_github_repo_name`), the attacker's validly-signed webhook (signed with *their own* org's `webhook_secret`) can write a fabricated CI status (`state`, `context`, `target_url`, `description`) onto a commit belonging to a stack in a completely different, unrelated repository/organization.

### Impact Explanation
Commit statuses gate `deployable?` and CI-required checks (`required_statuses`, `deploy.require_ci`) used by `DeploysController`/`Api::DeploysController` to decide whether a deploy can proceed without `force`/`require_ci` overrides, and by continuous deployment (`Stack.schedule_continuous_delivery`). Forging a passing status on a commit in a target stack that this attacker organization has no write access to can flip `commit.deployable?` to true and enable an **unauthorized deploy** to proceed through continuous delivery or a legitimate operator's UI click, without the target repository's real CI ever running. This satisfies the "unauthorized deploy" Critical impact bucket, since the binding broken is "organization authenticated (via signature) vs. repository/commit actually written."

### Likelihood Explanation
Requires the attacker to control (or be able to send webhooks for) at least one organization/repository already configured in `Shipit.github_teams`/onboarded with a `webhook_secret` in this instance, and requires a genuine SHA collision with a commit in the target stack. In practice, git SHA-1 collisions are hard to engineer for arbitrary victim commits, so this is more theoretical unless victim commit SHAs are predictable/reused (e.g. cherry-picks, shared cross-repo lineage, mirrors, submodules) — a realistic scenario in monorepo/mirrored-repo setups where the same commit legitimately exists in multiple `Repository` records tracked by different stacks.

### Recommendation
Scope `StatusHandler#process` (and any other handler using SHA-only lookups) to commits belonging to the repository declared in `payload.dig('repository','full_name')`, matching the pattern already used by `PushHandler`/`Handler#stacks`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or filtering `Commit.where(sha: params.sha, stack_id: stacks.pluck(:id))`, so the signature-verified organization/repository boundary carries through to the write.

### Proof of Concept
1. Attacker registers/owns `github-org-attacker/some-repo`, which is legitimately configured in this Shipit instance with its own `webhook_secret`.
2. Attacker crafts a commit whose SHA is engineered/known to collide with (or is a copy of) a commit SHA that already exists in `victim-org/critical-repo`'s tracked stack (e.g., because that exact commit was cross-merged/mirrored into both repos, which is common with shared library commits or submodule bumps).
3. Attacker sends a real GitHub `status` webhook for `github-org-attacker/some-repo`, correctly signed with their own `webhook_secret`, with `sha=<colliding sha>`, `state=success`, `context=<required CI context>`.
4. `WebhooksController#verify_signature` succeeds (signature is valid for attacker's own org).
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the commit row belonging to `victim-org/critical-repo`'s stack, and calls `create_status_from_github!`, marking it as passing the required check.
6. The victim stack's commit is now `deployable?`, permitting an operator or continuous-delivery job to deploy it without real CI having run. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
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
