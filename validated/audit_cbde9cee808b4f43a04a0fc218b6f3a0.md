### Title
`CheckSuiteHandler#process` resolves target stacks from an unauthenticated `repository.full_name` field, decoupled from the org that verified the webhook signature - ([File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify against using `repository_owner`, which is read from `payload.dig('repository','owner','login')`. `Handler#stacks` (used by `CheckSuiteHandler#process`) resolves the target repository from a *different* field in the same JSON object, `payload.dig('repository','full_name')`. Nothing in the code enforces that `full_name` actually belongs to `owner.login`, so a webhook that is validly signed for org A can address stacks/commits belonging to a completely unrelated repository/org B.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`repository_owner` (used to pick the verifying secret) == owner of `repository_name` (used to pick the affected `Stack`)

is false in general, because:

- `WebhooksController#verify_signature` computes the authenticating org as:
`params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) , and uses it to pick `Shipit.github(organization: repository_owner)` and validate `X-Hub-Signature` against that org's `webhook_secret` [2](#0-1) .
- `Handler#repository_name` independently reads `payload.dig('repository', 'full_name')` [3](#0-2) , and `Handler#stacks` resolves `Repository.from_github_repo_name(repository_name)` from that value with no reference to `repository_owner` [4](#0-3) .
- `Repository.from_github_repo_name` simply splits the string on `/` and does a `find_by(owner:, name:)` lookup [5](#0-4) , with no check that this owner matches the org that authenticated the request.
- `CheckSuiteHandler#process` then iterates `stacks.where(branch: params.check_suite.head_branch)` and, for matching commits, calls `schedule_refresh_check_runs!`, enqueuing `RefreshCheckRunsJob` [6](#0-5) .

Since `owner.login` and `full_name` are two independent keys inside the same `repository` JSON object in the payload, and neither `verify_signature` nor `Handler` cross-checks them, an attacker who can get a webhook signed under one org (`repository.owner.login = "attacker-org"`) can set `repository.full_name = "victim-org/victim-repo"` in the same request. The signature check passes (it never looks at `full_name`), and `stacks` resolves to the victim's `Repository`/`Stack` records regardless.

This is a defect of the shared `Handler` base class, not specific to `check_suite`; every handler built on `Handler#stacks`/`#repository_name` (push, pull_request variants, status, check_suite) inherits the same missing binding, but `CheckSuiteHandler` is the one in scope here.

Existing guards do not close this gap: `drop_unhandled_event` only checks the event name exists; the `ExplicitParameters` schema on `CheckSuiteHandler` only validates that `check_suite.head_sha`/`head_branch` are present strings, it says nothing about `repository`; `verify_signature`'s `rescue Shipit::GithubOrganizationUnknown` only guards against unknown org names, not against org/repo mismatch.

### Impact Explanation
A successfully-authenticated webhook for one org can enqueue `RefreshCheckRunsJob` against a `Stack`/`Commit` belonging to an unrelated, victim-owned `Repository`. The job itself fetches check runs using the victim stack's own `github_api`/credentials for the victim's real `github_repo_name` and `sha` [7](#0-6) , so it does not leak the app token to the attacker, but it does let the attacker force GitHub API calls and check-run state writes against a stack it has no authorization over, and can retrigger merge-queue evaluation via `stack.schedule_merges` if the check-run state changes [8](#0-7) . This is repeatable against any tracked repository whose `owner/name` the attacker can guess or observe, from any org that can obtain one validly-signed webhook, matching the "payload for one repository mutating another's stack/commit" category, though the practical blast radius is bounded by the job only re-syncing real GitHub-side state for the targeted commit rather than injecting arbitrary attacker data.

### Likelihood Explanation
Exploitability is entirely gated on the attacker being able to produce a request that passes `verify_webhook_signature` for *some* configured org. Per the stated rules, the attacker holds no `webhook_secret` for any org. `verify_webhook_signature` returns `true` unconditionally only if that org's `webhook_secret` is blank/unset [9](#0-8) , and a genuine, GitHub-signed delivery cannot have its `repository.full_name` altered afterward without invalidating the signature (the HMAC covers the full raw body). So this finding depends on either an operator leaving `webhook_secret` unset for a tenant org, or the attacker legitimately controlling their own org's app secret in a self-service multi-org setup (supported per `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`) — i.e., it requires a specific multi-tenant configuration rather than being universally exploitable against any default single-org Shipit install with a properly configured `webhook_secret`.

### Recommendation
In `Handler#stacks` (or `WebhooksController`), enforce that the resolved repository's owner matches the authenticated `repository_owner`/org used in `verify_signature` before executing any handler logic — e.g., pass the verified organization into `Handler.call`/`new` and reject (or scope `stacks` to) requests where `Repository.from_github_repo_name(repository_name).owner != verified_organization`.

### Proof of Concept
minitest plan (extends `test/controllers/webhooks_controller_test.rb` style, using the existing multi-org fixture `test/dummy/config/secrets_double_github_app.yml` with `OrgOne`/`OrgTwo`):

1. Configure `Shipit.secrets.github` with two orgs, `OrgOne` (attacker) and `OrgTwo` (victim), each with a distinct `webhook_secret`.
2. Create a victim `Stack` under `OrgTwo/victim-repo` tracking branch `master`, with a `Commit` of known `sha`.
3. Build a `check_suite` payload where `repository.owner.login = "OrgOne"` and `repository.full_name = "OrgTwo/victim-repo"`, `check_suite.head_branch = "master"`, `check_suite.head_sha = <victim commit sha>`.
4. Sign the raw body with `OrgOne`'s `webhook_secret` and set `X-Hub-Signature` accordingly; set `X-Github-Event: check_suite`.
5. POST to `/webhooks`.
6. Assert both sides of the equality: `repository_owner` resolved by the controller equals `"OrgOne"`, while `Repository.from_github_repo_name("OrgTwo/victim-repo").owner` equals `"orgtwo"` — i.e. they differ.
7. Assert `RefreshCheckRunsJob` is enqueued with `commit_id: victim_commit.id`, proving a request authenticated for `OrgOne` mutated job state tied to `OrgTwo`'s stack/commit.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/commit.rb (L186-196)
```ruby
    def refresh_check_runs!
      paginated_check_runs do |check_runs|
        check_runs.each do |check_run|
          create_or_update_check_run_from_github!(check_run)
        end
      end
    end

    def create_or_update_check_run_from_github!(github_check_run)
      check_runs.create_or_update_from_github!(stack_id, github_check_run)
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
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
