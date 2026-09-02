### Title
Cross-repository commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits solely by `Commit.where(sha: params.sha)`, with no check that the webhook's `repository` matches the stack that owns the matched commit(s). Because GitHub webhook signatures in this engine are verified per-organization (not per-repository), any repository inside an organization that already has Shipit's GitHub App installed can emit a legitimately-signed `status` event whose attacker-controlled `description`/`context`/`target_url` gets written as a `Shipit::Status` row against a commit belonging to a completely different stack/repository, as long as the two repos happen to share a commit SHA (trivial via forking/cherry-picking identical commit objects, since SHA1 is purely content-derived and independent of which repo stores the object).

### Finding Description
The claimed binding: `stack.repository == commit.status.repository` — i.e., the repository that authored a status should be the repository whose Stack/UI renders it. This binding is broken not at the `stack_id` assignment (which is internally consistent, taken from the matched `Commit#stack_id`) but one level up, at commit resolution: [1](#0-0) 

`StatusHandler#process` calls `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. The `params` schema only requires `sha`/`state` and accepts `description`, `target_url`, `context`, `created_at`, `branches` — there is no `repository` field checked against the found commit's stack: [2](#0-1) 

`Commit#create_status_from_github!` then persists the status using the matched commit's own `stack_id`: [3](#0-2) 

The only gate before this handler runs is `WebhooksController#verify_signature`, which authenticates against `Shipit.github(organization: repository_owner)` — i.e. it validates the signature using the **organization-level** GitHub App webhook secret, not a repository-specific secret: [4](#0-3) [5](#0-4) 

This means the signature check proves "this event genuinely came from GitHub for *some* repository in this organization" — it proves nothing about which specific repository/stack the event concerns, and `StatusHandler` never re-checks that.

Exploit flow:
1. Attacker is a member (or any actor able to create/push a repository) within an organization `Org` where Shipit's GitHub App is already installed (this is required for the org-level `webhook_secret` to exist and validate — a precondition of the organization already using Shipit, not of the attacker having any Shipit privilege).
2. Attacker identifies a target commit SHA already tracked by a victim's Shipit stack (commit SHAs of public/PR commits are visible; git SHA1 is a pure hash of tree/parents/author/committer/timestamps/message, so pushing an object with byte-identical content — e.g. forking or replaying the victim repo's history into a new repo in `Org` — reproduces the exact same SHA).
3. Attacker posts a commit status via the normal GitHub Statuses API against their own repository/commit with `state`, and arbitrary `description`, `target_url`, `context` strings (e.g. containing markup).
4. GitHub delivers a `status` webhook to Shipit, correctly signed with `Org`'s webhook secret.
5. `WebhooksController#verify_signature` passes (org-level secret matches). `StatusHandler#process` runs `Commit.where(sha: ...)`, matches the victim's pre-existing `Commit` row (which belongs to the victim's stack, unrelated to the attacker's repo), and calls `create_status_from_github!`, writing a `Shipit::Status` with `stack_id = victim_commit.stack_id` and attacker-supplied `description`/`context`/`target_url`.
6. This row is subsequently rendered in the victim stack's UI (status list, commit detail) with no sanitization tied to origin repository, since the model has no notion that this data crossed a trust boundary.

Existing guards do not stop this: `verify_signature` authenticates the organization, not the specific repository named in the payload; `drop_unhandled_event` only checks the event type is handled; the `ExplicitParameters` schema for `StatusHandler` has no `repository` requirement or cross-check; there is no `stacks` scoping, no `Repository`/`Stack` validation, and no `EnvironmentVariables#permit`-style filter applicable here.

### Impact Explanation
An unprivileged repository owner/contributor within any organization already onboarded to Shipit can inject attacker-chosen strings (`description`, `context`, `target_url`) into another tenant's `Shipit::Status` record and have them rendered in that victim stack's UI — this is a "payload for one repository mutating another's stack/commit" as defined in Critical severity. It is repeatable against any victim commit whose SHA the attacker can reproduce (which is trivial for any commit that is/was part of a public or shared history, e.g. via fork), and against any stack in the same GitHub organization. Beyond UI content injection, the forged status also affects `Commit#state`/`deployable?` computation and can trigger `deployable_status`/`commit_status` hooks and even continuous-delivery merge/deploy scheduling (`stack.schedule_merges`) for the victim stack, since `add_status` reacts to state transitions regardless of who authored the underlying webhook ( [6](#0-5) ). This can influence whether a victim's commit is considered deployable/mergeable — an unauthorized-deploy-adjacent impact.

### Likelihood Explanation
Preconditions: (a) the organization already has Shipit's GitHub App installed (webhook secret configured) — a standard, common setup; (b) the attacker can create or push to some repository within that same organization and can also create commits whose SHA matches an existing tracked commit — trivially achieved by forking/copying an existing public commit's exact git object into a new location, or, for organizations that permit member-created repos, simply pushing the victim's already-public commit history into a new repo. No Shipit session, API token, or GitHub secrets are needed — only ordinary GitHub push/API access to a repo in the shared org, which matches the described unprivileged threat model. This is fully repeatable per targeted commit/stack.

### Recommendation
In `StatusHandler#process`, restrict commit lookup to commits whose stack matches the webhook's `repository.full_name` (require and validate a `repository` param, mirroring how `PushHandler` resolves the target `Stack`/`Repository`), instead of a global `Commit.where(sha:)` scan. Additionally, consider moving webhook signature verification to be repository/stack-scoped where possible instead of solely organization-scoped, to reduce the blast radius when SHAs collide across repositories in the same org.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook writes into a commit's own stack based only on sha, with no repository check" do
  victim_stack = shipit_stacks(:shipit)          # e.g. repo "shopify/shipit-engine"
  other_stack  = shipit_stacks(:cyclimse)        # e.g. repo "attacker-org/some-fork", different tenant

  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "m", author: shipit_users(:shipit),
    committer: shipit_users(:shipit), authored_at: Time.now, committed_at: Time.now)

  # Attacker forges a status webhook payload that only references the shared sha,
  # with no binding to victim_stack's repository at all.
  forged_params = Shipit::Webhooks::Handlers::StatusHandler::Params.new(
    sha: shared_sha, state: 'success',
    description: '<script>alert(1)</script>',
    context: 'attacker/ci', target_url: 'https://attacker.example/x'
  )

  Shipit::Webhooks::Handlers::StatusHandler.new.process_for_test(forged_params) # or call handler.call(payload_hash)

  status = victim_commit.reload.statuses.last
  assert_equal victim_stack.id, status.stack_id           # binding claimed: stack == originating repo's stack
  assert_equal '<script>alert(1)</script>', status.description # attacker payload persisted verbatim on victim's stack
end
```
This demonstrates that a status resolved purely by SHA is attached to `victim_stack` even though nothing in the forged payload authenticated or referenced `victim_stack`'s repository, confirming the cross-tenant write.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
