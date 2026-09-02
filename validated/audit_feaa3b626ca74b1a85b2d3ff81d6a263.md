### Title
Cross-tenant stack reactivation via full_name/owner.login mismatch bypassing webhook signature scoping - (File: `app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook by looking up the GitHub App/`webhook_secret` for `params.dig('repository','owner','login')` (or `organization.login`), but `ReopenedHandler` (and every other `pull_request` handler) resolves the target `Repository`/`Stack` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, an entirely separate field that is never cross-checked against `owner.login`. This lets a webhook validly signed for organization A carry a `repository.full_name` pointing at organization B's repository, letting A's webhook reach into and mutate B's stacks.

### Finding Description
Binding claimed to hold: `organization_that_signed_webhook (params.dig('repository','owner','login'))` == `organization_owning_target_stack (owner segment of params.repository.full_name)`.

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and fetches `Shipit.github(organization: repository_owner)` to validate `X-Hub-Signature` against that organization's `webhook_secret`.
- After signature validation succeeds, `WebhooksController#create` dispatches the parsed JSON body unmodified to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) .
- `ReopenedHandler#repository` does `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and `Repository.from_github_repo_name` splits `full_name` into `owner/name` and does a DB lookup — completely independent of the `owner.login` field used during signature verification [2](#0-1) [3](#0-2) .
- If `repository.review_stacks_enabled && provisioning_behavior_allow_all?`, `ReopenedHandler#process` calls `stack.unarchive!` (the `ReviewStackAdapter`), which re-queues `ReviewStackProvisioningQueue.add(stack)` and calls `stack.unarchive!` inside a transaction, with no additional authorization check [4](#0-3) .
- Nowhere in `Handler` (the base class), `ExplicitParameters` schema, or any handler is `params.repository.full_name`'s owner segment compared against `params.repository.owner.login` (or `sender.login`) — I confirmed this by reviewing `Handler#stacks`/`repository_name` [5](#0-4)  and every `pull_request` handler's `repository` method (`reopened_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `closed_handler.rb`, `assigned_handler.rb`, `edited_handler.rb`, `label_capturing_handler.rb`) — they all use `params.repository.full_name` exclusively, and none reference `owner.login`.

Exploit flow: attacker administers a GitHub App/org ("attacker-org") that is legitimately configured in Shipit's multi-org `github:` secrets block (per `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`), so they know or can produce a valid HMAC over an arbitrary raw POST body using that org's `webhook_secret`. They POST directly to `/webhooks` with `X-Github-Event: pull_request`, a JSON body where `repository.owner.login = "attacker-org"` (so `verify_signature` selects and validates against the org they control) but `repository.full_name = "victim-org/victim-repo"` and `action = "reopened"`. Signature check passes because it only validates against `attacker-org`'s secret, not against `full_name`. The handler then resolves the *victim's* `Repository`/`Stack` via `full_name` and, if that repo has `review_stacks_enabled` and `provisioning_behavior_allow_all`, unarchives and re-queues a previously-archived victim `ReviewStack` for provisioning.

Existing guards do not catch this: `verify_signature` only authenticates that *some* known organization's secret produced the signature; it never asserts that authenticated organization is the one referenced by `full_name`. `ExplicitParameters` schemas only validate presence/type, not cross-field consistency. `drop_unhandled_event` and `check_if_ping` are irrelevant. `Stack#deployable?` is never consulted before `unarchive!`, confirming the premise, but that alone is not the root cause — the root cause is the missing full_name/owner.login binding check.

### Impact Explanation
A webhook payload signed for one tenant organization can reactivate (unarchive + re-queue for provisioning) a review stack belonging to a completely different tenant organization's repository, without any relationship between the two. This is an authorization bypass allowing a payload/credential scoped to one repository to mutate another repository's stack state (matches the "payload for one repository mutating another's stack" Critical category). It re-triggers `ReviewStackProvisioningQueue`/`GithubSyncJob` machinery against a stack the real maintainers deliberately archived, and is repeatable against any repository configured with `review_stacks_enabled` + `provisioning_behavior_allow_all` across the whole multi-tenant Shipit instance, as long as the attacker controls the webhook_secret of any one configured organization.

### Likelihood Explanation
This requires: (1) Shipit configured for multiple GitHub organizations, each with independently known webhook secrets (a documented, supported configuration per `docs/setup.md`); (2) the attacker controls at least one such organization's webhook_secret (i.e., is a legitimate but lower-trust tenant of the shared Shipit instance) — this is a real but narrower attacker capability than "any random internet user," since it requires being one of the configured GitHub orgs' admins; (3) the victim repository has `review_stacks_enabled` and `provisioning_behavior_allow_all` (or matching label behavior) and has an archived `ReviewStack`. Given those preconditions, the attack is a single crafted HTTP POST, fully repeatable and scriptable against any victim repo/environment name known to the attacker (`pr<number>`).

### Recommendation
In `WebhooksController#verify_signature` (or immediately after, before dispatching to handlers), assert that `params.dig('repository','full_name')`'s owner segment equals `params.dig('repository','owner','login')` (reject/422 on mismatch). Additionally/alternatively, have `Repository.from_github_repo_name` and all `pull_request` handlers resolve the repository via the authenticated `repository_owner` rather than trusting `full_name` alone, e.g., scope the lookup by `owner: repository_owner` explicitly rather than parsing it back out of an untrusted `full_name` field.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`:
1. Create `victim_repository` (owner: `"victim-org"`, name: `"victim-repo"`, `review_stacks_enabled: true`, `provisioning_behavior: :allow_all`) and an archived `ReviewStack` under it (`stack.archive!`).
2. Build a `pull_request_reopened` payload with `payload["repository"]["full_name"] = "victim-org/victim-repo"` and `payload["repository"]["owner"]["login"] = "attacker-org"`.
3. Stub `Shipit.github(organization: "attacker-org")` (or `Shipit.github`) `.verify_webhook_signature` to return `true` (simulating a signature validly produced with attacker-org's own secret), while leaving `victim-org`'s configuration untouched/stubbed as failing if consulted.
4. POST to `/webhooks` with `X-Github-Event: pull_request` and the crafted body/signature.
5. Assert: `stack.reload.archived?` is now `false`, and `Shipit::ReviewStackProvisioningQueue.add` was called with `stack` — demonstrating the victim stack under `victim-org` was reactivated using only `attacker-org`'s credentials, with the equality `repository_owner (attacker-org) == full_name owner (victim-org)` false both before and after, yet the mutation still occurred.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
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
