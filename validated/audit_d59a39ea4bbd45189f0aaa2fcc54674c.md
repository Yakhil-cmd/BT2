### Title
Cross-repository/cross-stack Status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits by a bare SHA lookup across the entire `commits` table with no repository or stack scoping, then writes a `Status` row onto every matching row. Because GitHub webhook signature verification only authenticates that a payload came from a given organization/repository — it does not constrain which DB rows the handler is allowed to mutate — a `status` webhook that is legitimately authenticated for one repository can write a `codecov/project` success status onto an unrelated stack's commit if that stack happens to hold a commit row with an identical SHA.

### Finding Description
The broken binding: the invariant the question states should hold is
`webhook.authenticated_repository == status.written_to.commit.stack.repository`
but the code actually enforces only
`webhook.signature valid for Shipit.github(organization: repository_owner)`,
with no further check that the mutated `Commit`/`Status` rows belong to that repository.

Path:
- `Shipit::WebhooksController#create` parses the raw payload and dispatches to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature`, which validates the HMAC against `Shipit.github(organization: repository_owner)` only — it authenticates the org/app secret, not a specific repository or stack [1](#0-0) .
- `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global lookup by SHA with **no** `repository_name`/`stacks` scoping, unlike the base `Handler` class which does expose a repository-scoped `stacks` helper that `StatusHandler` simply does not use [2](#0-1) [3](#0-2) .
- `create_status_from_github!` writes the status keyed only by the commit's own `stack_id`, whichever stack that commit row happens to belong to: `statuses.replicate_from_github!(stack_id, github_status)` [4](#0-3) , and `Status.replicate_from_github!` persists `state`, `context`, etc. directly from attacker-controlled webhook fields [5](#0-4) .
- The commits table's uniqueness constraint is `(stack_id, sha)` (per migration `20170524104615_index_commits_on_stack_id_and_sha.rb`), which structurally guarantees that the *same literal SHA* can independently exist as separate rows in unrelated stacks — the schema does not treat SHA as globally unique.
- `required?`/`blocking?`/`deployable?` are computed per-stack from `commit.required_statuses`/`commit.blocking_statuses` [6](#0-5) , so flipping the status on the victim stack's commit row directly changes that stack's deployability/mergeability, independent of which repository actually sent the webhook.

Exploit flow: an attacker who can read a target (often public) repository's commit history can duplicate an existing commit object byte-for-byte (same tree, parents, author/committer, timestamps, message) into a branch/PR they control in a *different* repository (their own fork/repo, potentially in the same GitHub org so a real, correctly-signed webhook can be produced). This literal duplication reproduces the identical SHA1 (git SHAs are content-addressed, not repository-addressed). The attacker then causes any CI integration (e.g., codecov) on their own controlled repository to post a `success` status with `context: codecov/project` for that SHA. GitHub delivers a genuinely signed `status` webhook naming the attacker's own repository, which passes `verify_signature`. `StatusHandler#process`, however, matches on bare SHA and updates the `Status` for **every** commit row sharing that SHA — including the row belonging to the unrelated victim stack (e.g. a `review_stacks_enabled true, allow_all` stack that auto-provisions review-stack instances executing `shipit.yml` for external PRs, per `OpenedHandler#provision?`) [7](#0-6) . This can satisfy a required context or clear a blocking one on the victim stack that never authorized or received that CI result.

Existing guards do not catch this: `verify_signature` authenticates organization/app identity, not the write target [8](#0-7) ; `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape of `sha`/`state`/`context`, not ownership; there is no repository/stack scoping anywhere in `StatusHandler`.

### Impact Explanation
A `status` payload authenticated for repository A can write a `Status` record into a stack belonging to repository B (or a different stack of the same repository) purely because the two hold commit rows with an identical SHA, changing that victim stack's `deployable?`/`required?`/`blocking?` evaluation and potentially unblocking an unauthorized deploy, rollback, or auto-merge on the victim stack — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Blast radius is any stack/repository in the same Shipit instance whose commit history happens to intersect (share a duplicated commit object) with a repository the attacker controls or can influence CI on.

### Likelihood Explanation
Exploitation requires: (1) the victim repository/stack is public or otherwise readable so the attacker can obtain the exact byte content of a target commit to duplicate; (2) the attacker controls (or can trigger CI on) some repository within reach of the same GitHub App/organization so a real webhook signature is produced; (3) the duplicated commit is actually present as a tracked `Commit` row in the victim stack (e.g. an ancestor commit on the mainline the victim stack is tracking). This is not a hash-collision attack — it's exact content duplication, which is feasible against public history but constrains which specific commit can be targeted (an already-existing, known commit, not an attacker-chosen new one). It is repeatable for any commit the attacker can duplicate and get any real status provider to report on.

### Recommendation
Scope `StatusHandler#process` to the repository that authenticated the webhook, mirroring the `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name).stacks.commits.where(sha: params.sha)`), or add a `Commit` uniqueness/lookup path scoped by `stack_id`/`repository_id` so a status webhook can only mutate commits belonging to stacks under the repository named in the authenticated payload.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, hypothetical):
1. Create `repository_a` (attacker-controlled) and `repository_b` (victim), each with a `Stack`. Give `repository_b`'s stack `review_stacks_enabled: true`, `provisioning_behavior: :allow_all`, and configure it to `require` `codecov/project`.
2. Create two `Commit` rows with the **same** `sha` value, one under `repository_a`'s stack and one under `repository_b`'s (victim) stack, asserting `Shipit::Commit.where(sha: shared_sha).count == 2` and that they belong to different `stack_id`s (`commit_a.stack_id != commit_b.stack_id`), and before the webhook, `commit_b.deployable? == false` / `commit_b.required?` for `codecov/project` is unmet.
3. Build a `status` webhook payload naming `repository_a` (`context: 'codecov/project', state: 'success', sha: shared_sha`).
4. Call `Shipit::Webhooks::Handlers::StatusHandler.new(payload).process` (or POST through `WebhooksController` with `verify_signature` stubbed true, per existing test pattern in `test/controllers/webhooks_controller_test.rb`).
5. Assert `commit_b.reload.statuses.where(context: 'codecov/project', state: 'success').exists?` is `true` and `commit_b.deployable?`/merge status flips to success — proving repository A's authenticated payload mutated repository B's (victim) commit/stack state, violating the stated invariant.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L23-33)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
