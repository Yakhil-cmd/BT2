Found the key mismatch: `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) resolves the target commits by a **global** `Commit.where(sha: params.sha)` lookup, completely bypassing the `repository_name`/`stacks` scoping that `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) provides and that `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) correctly uses. Since git SHAs are content-addressed, the same 40-hex commit can legitimately exist in multiple unrelated repositories tracked by different Shipit stacks (e.g., a shared base commit, a forked/duplicated history, or simply an attacker-controlled repo crafted to reuse a SHA already present in a victim stack).

However, exploiting this requires an attacker to control a GitHub webhook delivery whose signature validates for *some* organization Shipit trusts (`WebhooksController#verify_signature`, `app/controllers/shipit/webhooks_controller.rb:24-49`, using the per-organization `webhook_secret` from `Shipit.github(organization:)`). The signature only proves the payload came from a repo owned by that organization — it does not bind the `sha` field to that organization's actual repositories. Because `StatusHandler` ignores `repository_name` entirely, any org whose webhook secret validates (any org that has *any* Shipit-connected repo) can post a `status` event with an arbitrary `sha` and flip CI status (`state`, `context`, `description`) on a commit belonging to a **completely different, unrelated stack/repository** it doesn't own — as long as that SHA happens to match a commit row Shipit already has, which is fully attacker-discoverable (SHAs are public on GitHub, and Shipit's own UI/API exposes commit SHAs per stack).

This breaks the binding: **organization authenticated by the webhook signature ≠ repository whose commit-status/deployability is written**, matching the CometBFT bug-class of "peer identity that authenticates a message being trusted to act on state (target height / commit) that message doesn't actually own."

### Title
Cross-repository CI status forgery via unscoped commit lookup in StatusHandler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` updates commit statuses by a bare `Commit.where(sha: params.sha)` query with no repository scoping, unlike `PushHandler` which correctly scopes to `stacks` derived from the webhook's `repository.full_name`. A `status` webhook whose signature is valid for organization A can therefore write CI status onto a commit belonging to a stack owned by an unrelated repository/organization B, purely because the SHA text matches.

### Finding Description
`Handler#stacks` and `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) exist precisely to scope webhook effects to the repository that sent the event. `PushHandler` uses this correctly: `stacks.not_archived.where(branch:).find_each { ... }` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`). `StatusHandler`, however, never calls `stacks` or `repository_name` at all — it queries `Commit.where(sha: params.sha)` globally across the entire `commits` table and calls `commit.create_status_from_github!(params)` on every match (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`). Since `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) only proves the payload's HMAC matches the `webhook_secret` configured for the organization derived from the payload's own `repository.owner.login`/`organization.login` (`app/controllers/shipit/webhooks_controller.rb:59-61`), it authenticates "this came from a registered GitHub App installation for org X" — it does not authenticate "org X owns commit SHA S." `StatusHandler` conflates the two.

### Impact Explanation
An attacker who controls (or compromises) any repository connected to Shipit — even a low-value one in an unrelated organization — can send `status` webhook events (which GitHub lets any repository admin/CI integration configure) with a `sha` copied from a target stack's commit history and an arbitrary `state`/`context`/`description`. This can flip a required CI check to `success` on a victim stack's commit that has not actually passed CI, since `deployable?`/`required_statuses`/blocking-status logic (`app/models/shipit/status/common.rb:38-52`, referenced in `test/models/commits_test.rb:574-600`) reads directly from `Commit#statuses`. If that commit is `deployable?`, it can be used to trigger or unblock an actual deploy via `Stack#trigger_deploy`, constituting an unauthorized deploy path that crosses a repository trust boundary the attacker was never granted write access to.

### Likelihood Explanation
Requires an attacker to have write/webhook-configuration access to *any* repository already connected to a Shipit-managed GitHub App installation, and requires the target SHA to already exist as a `Shipit::Commit` row (discoverable from the target stack's public commit history/API). No `ApiClient` token, no GitHub org membership on the victim org, and no privileged Shipit account is needed — only a signed webhook from an unrelated, lower-trust repository.

### Recommendation
Scope `StatusHandler#process` the same way as `PushHandler`: resolve `stacks` via `repository_name` from the payload and restrict the `Commit` lookup to commits belonging to those stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or an equivalent `Commit.where(sha: params.sha, stack: stacks)`.

### Proof of Concept
1. Attacker owns/administers `attacker-org/throwaway-repo`, which is connected to the same Shipit instance (any stack works) and thus has a valid `webhook_secret` for `attacker-org`.
2. Attacker looks up a commit SHA `S` on the victim stack `victim-org/prod-app` (public commit history / Shipit stack page).
3. Attacker sends a `status` webhook event to Shipit's `/webhooks` endpoint, correctly HMAC-signed with `attacker-org`'s `webhook_secret`, with body `{"sha": "S", "state": "success", "context": "ci/required-check", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/throwaway-repo"}}`.
4. `WebhooksController#verify_signature` passes because the signature matches `attacker-org`'s secret.
5. `StatusHandler#process` runs `Commit.where(sha: "S")`, finds the victim's commit row (owned by `victim-org/prod-app`), and calls `create_status_from_github!`, setting `context: "ci/required-check"` to `success` — regardless of `attacker-org` having no relationship to `victim-org`'s stack. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
```
