### Title
Cross-repository CI status forgery via organization/repository binding mismatch in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The `WebhooksController#verify_signature` selects the HMAC secret to validate an incoming webhook using the organization derived from the payload (`repository.owner.login` or `organization.login`), but `Shipit::Webhooks::Handlers::StatusHandler#process` looks up the target `Commit` purely by `sha`, with **no scoping to the repository/organization** that was authenticated. This breaks the binding "organization whose secret authenticated the request == repository/stack that is written."

### Finding Description
`WebhooksController#verify_signature` resolves which `GitHubApp`/webhook secret to use via `repository_owner`, taken from the untrusted JSON body itself: [1](#0-0) [2](#0-1) 

Shipit explicitly supports one GitHub App/webhook secret per organization ("Using Multiple GitHub Applications"), so an admin of one onboarded organization (Org A) legitimately possesses the webhook secret for Org A: [3](#0-2) 

After signature verification, dispatch simply calls the registered handler for the event with the full, attacker-controlled JSON body: [4](#0-3) 

For the `status` event, `StatusHandler#process` looks up commits **globally by `sha`**, without any reference to `repository`, `stacks`, or the `repository_owner` used for signature verification: [5](#0-4) 

This is unlike `PushHandler` and `CheckSuiteHandler`, which correctly scope their effect to `stacks` resolved from `payload.dig('repository', 'full_name')` via the base `Handler#stacks`/`#repository_name`: [6](#0-5) [7](#0-6) [8](#0-7) 

The equality that should hold is: `organization whose secret validated the request == organization/repository that owns the record being mutated`. `StatusHandler` breaks this: the signature is validated against Org A's secret (derived from the attacker-supplied `repository.owner.login` field, which need not correspond to any commit actually touched), while the record mutated (`Commit.where(sha: params.sha)`) can belong to **any stack in the Shipit instance**, including repositories owned by a completely unrelated Org B that the attacker has no access to.

`create_status_from_github!` then feeds directly into the commit's `status`/`deployable?`/merge-queue evaluation and schedules merges: [9](#0-8) [10](#0-9) [11](#0-10) 

### Impact Explanation
An attacker who administers/controls the GitHub App or webhook configuration for one organization onboarded to a shared Shipit instance (i.e., knows only their own org's `webhook_secret`) can forge a `status` webhook whose `repository.owner.login` is their own org (so it passes `verify_webhook_signature`) but whose `sha` matches a commit belonging to a **different organization's** stack. Because `StatusHandler` never checks that the commit's stack belongs to the authenticated organization, the attacker can inject arbitrary CI `state`/`context`/`description` (e.g., a fake "success") onto a commit in a repository they do not control. Since `deployable?`, `blocked?`, and `schedule_merges` are all driven by commit status, this can unblock or trigger an unauthorized deploy/merge for a stack outside the attacker's authorization boundary — matching the High-impact category "escalation ... or an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Likelihood is constrained: it requires the attacker to legitimately hold a webhook secret for at least one organization connected to the shared Shipit instance (a realistic scenario for any multi-tenant Shipit deployment per the documented "Using Multiple Github Applications" setup), and requires knowledge/guessing of a target commit SHA belonging to another tracked repository (SHAs are often publicly visible, e.g., via GitHub commit URLs, PRs, or CI logs). No GitHub App private key, `ApiClient` token, or Shipit session is required — only knowledge of one org's `webhook_secret`, which is exactly the credential boundary this analog is permitted to assume is held by an unprivileged-relative-to-the-victim-org attacker.

### Recommendation
In `StatusHandler` (and any other handler that doesn't already scope through `stacks`/`Handler#repository_name`), restrict the `Commit` lookup to commits belonging to stacks under the repository/organization that was actually authenticated by `verify_webhook_signature`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or by requiring and validating `params.repository.full_name` against `Repository.from_github_repo_name` before touching any commit, exactly as `PushHandler` and `CheckSuiteHandler` do. More generally, `WebhooksController#verify_signature` should ensure the organization used to select the signing secret is the same organization whose resources every handler subsequently mutates, rather than trusting the unauthenticated `repository.owner.login`/`organization.login` fields independently per handler.

### Proof of Concept
1. Assume Shipit is configured with two GitHub App installations, one for `org-a` and one for `org-b`, each with a distinct `webhook_secret` per the documented multi-org config.
2. Attacker administers `org-a`'s GitHub App installation and thus knows `org-a`'s `webhook_secret`.
3. Attacker crafts a `status` event payload:
```json
{
  "sha": "<sha of a commit belonging to org-b/victim-repo, tracked by Shipit>",
  "state": "success",
  "context": "ci/forced",
  "repository": { "owner": { "login": "org-a" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(org-a's webhook_secret, raw_body)` and POSTs to `/webhooks`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-a"`, fetches `Shipit.github(organization: "org-a")`, and the signature validates successfully because it was computed with `org-a`'s real secret.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the commit that actually belongs to `org-b/victim-repo`'s stack (no scoping check), then calls `commit.create_status_from_github!(params)`, injecting a forged `"success"` status onto a commit in a repository the attacker never had access to — potentially unblocking or triggering the merge queue / deploy for `org-b`'s stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
