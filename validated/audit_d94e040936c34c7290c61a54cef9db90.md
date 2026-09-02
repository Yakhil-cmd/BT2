### Title
Commit-status webhook writes are not scoped to the authenticated repository, enabling cross-repository CI status forgery - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub organization derived from the payload's `repository.owner.login` (or `organization.login`), and then dispatches the payload to a handler that is expected to act only within that repository's scope. `PushHandler` and `CheckSuiteHandler` correctly resolve `stacks`/`commits` by joining through `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, but `StatusHandler` bypasses this scoping entirely and mutates `Commit` rows matched only by `sha`, globally across every repository/organization managed by the Shipit instance.

### Finding Description
`WebhooksController#verify_signature` picks the HMAC secret to validate the request with by resolving the GitHub App config for `repository_owner`, which is read straight from the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`): [1](#0-0) [2](#0-1) 

This signature check proves only that *some* org configured in Shipit's `secrets.yml` sent this payload — it never fixes which repository the handler is permitted to mutate. `Handler` base class exposes a `stacks` helper that is properly scoped to the repository named in the payload: [3](#0-2) 

`PushHandler` and `CheckSuiteHandler` both use this scoped `stacks`/`stack.commits` relation before touching any `Commit`: [4](#0-3) [5](#0-4) 

`StatusHandler`, however, ignores `payload['repository']` entirely and updates any commit in the database whose `sha` matches, with no repository/stack filter at all: [6](#0-5) 

The equality that should hold but is broken: `organization/repository the webhook signature authenticates == repository whose commits are written by the handler`. For `push`/`check_suite` this equality holds (both sides resolve through `Repository.from_github_repo_name(payload['repository']['full_name'])`). For `status`, the left side is the org that owns whatever repository sent the webhook, while the right side is *every* `Commit` row in the whole Shipit instance sharing that `sha`, regardless of which `Stack`/`Repository`/organization it belongs to.

### Impact Explanation
Because commit SHAs are content-addressed and frequently shared across forks, mirrors, or repositories with common history (a very common multi-tenant Shipit setup, as evidenced by `config/secrets.development.shopify.yml` configuring multiple independent GitHub orgs under one Shipit instance), an actor who can generate a legitimately-signed `status` webhook from *any* onboarded organization/repository can forge a commit status (`state`, `context`, `target_url`, `description`) on a `Commit` belonging to a completely different stack/repository/organization, as long as that commit's SHA is also tracked there. Since `ci.require` (referenced in `README.md`) gates deploy eligibility on commit statuses, this allows an attacker who only controls a repository in one tenant to make a commit in an unrelated tenant/repository appear to pass CI, which can unblock an unauthorized deploy on that other stack. This crosses a repository/organization trust boundary using only the writer's own (unprivileged, relative to the victim repository) GitHub webhook delivery rights — matching the required "cross-repository writes" / "unauthorized deploy" impact bar.

### Likelihood Explanation
Exploitability requires: (1) the attacker controls or can trigger a `status` event from any repository in any organization already configured in the shared Shipit instance's `secrets.yml` (a realistic condition for shared/internal multi-tenant Shipit deployments, as shown by the two-org example in `config/secrets.development.shopify.yml`), and (2) a commit SHA collision/overlap between the attacker's repository and the victim stack's repository (common for forks, mirrors, shared submodules, or cherry-picked commits). This is plausible but not universal, so likelihood is moderate rather than trivial — it depends on deployment topology (single-org installs are unaffected) and on SHA overlap between repositories.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler`/`CheckSuiteHandler` do: resolve the target commits via `stacks`/`Repository.from_github_repo_name(payload.dig('repository','full_name'))` instead of a bare `Commit.where(sha: params.sha)` lookup, so a status update can only affect commits belonging to the repository that was actually authenticated by the webhook signature.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own GitHub App and `webhook_secret` (as in `config/secrets.development.shopify.yml`), both with stacks tracked in the same Shipit instance.
2. Attacker has push/webhook-triggering rights on a repo in `org-a` and creates a commit whose SHA is identical to a commit already tracked in `org-b`'s stack (e.g., by cherry-picking/forking a commit from `org-b`'s public history into their own `org-a` repository).
3. Attacker triggers (or has CI generate) a `status` event for that SHA in their `org-a` repository, setting `state: success`. GitHub signs this payload with `org-a`'s real webhook secret.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `org-a` from the payload and validates the signature successfully against `org-a`'s secret.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` with no repository filter, finds the matching commit under `org-b`'s stack, and calls `create_status_from_github!`, marking that commit's CI status as `success` in `org-b`'s stack — a write the attacker has no authorization to make.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
