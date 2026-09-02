### Title
Cross-organization commit-status forgery via unscoped `StatusHandler` webhook lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
Shipit's webhook signature verification authenticates a request against a single GitHub *organization* (the org whose `webhook_secret` matches), but `StatusHandler` — unlike the other webhook handlers — never checks that the `Commit` it mutates actually belongs to a repository owned by that authenticated organization. This breaks the binding "organization authenticated == repository written."

### Finding Description
`WebhooksController#verify_signature` selects the HMAC secret to verify against based on the attacker-controlled `repository`/`organization` field of the payload, and only continues processing if the signature matches that org's configured `webhook_secret`: [1](#0-0) [2](#0-1) 

This authenticates that the request came from a party who knows the webhook secret of *some* organization configured in Shipit — it says nothing about which repository's data may legitimately be mutated. Shipit explicitly supports hosting multiple, independently-administered GitHub organizations on one instance, each with its own `webhook_secret`: [3](#0-2) 

Once the signature is accepted, `WebhooksController#create` dispatches the raw, unscoped `params` to the handler for the event type: [4](#0-3) 

The base `Handler` class exposes a `stacks` helper that correctly re-scopes any action to the repository named in the payload: [5](#0-4) 

`PushHandler` and `CheckSuiteHandler` both use this `stacks` scoping before acting on a SHA: [6](#0-5) [7](#0-6) 

`StatusHandler`, however, looks up the target `Commit` **globally**, by SHA alone, with no repository/organization scoping at all: [8](#0-7) 

So the equality that should hold — *organization whose secret verified the signature* == *organization owning the repository/commit that gets written* — is never checked for `status` events. Any org's valid webhook secret authenticates writes against any commit on the entire Shipit instance, as long as the attacker can guess or learn its 40-character SHA (trivial for public repositories, or for private repos whose SHAs leak via other webhooks, PR pages, CI logs, etc.).

### Impact Explanation
Commit statuses recorded via `create_status_from_github!` feed into a stack's deployable/status-check gating used to decide whether a commit is safe to deploy. An attacker who legitimately administers a GitHub App installation for their *own* onboarded organization (and therefore knows their own org's `webhook_secret`) can forge a `status` webhook naming a commit SHA belonging to a *different* tenant organization's repository, injecting a fabricated `success` status for a required CI context. This can flip that unrelated stack's deployable/status-check state and enable an unauthorized deploy of a commit whose real CI checks never passed — a cross-tenant integrity break that falls under "an unauthorized deploy."

### Likelihood Explanation
Requires only: (1) legitimate webhook-secret knowledge for one organization hosted on a shared, multi-org Shipit instance (an intended, documented deployment topology), and (2) the target commit SHA, which is generally discoverable for the target repository (public repos trivially; private repos via other observable signals). No privileged Shipit session, GitHub App private key, or `api_clients_secret` is required — only the webhook HMAC secret of any one onboarded org, which the rules treat as an available "authentication" boundary rather than a privileged secret internal to the target org.

### Recommendation
In `StatusHandler#process` (and any other handler acting on payload-derived identifiers), scope the lookup through `stacks`/`repository_name` derived from the payload's `repository.full_name`, and cross-check that this repository belongs to the organization that was actually used to verify the signature (`repository_owner` in `WebhooksController`), rejecting the event if they diverge, analogous to how `PushHandler` and `CheckSuiteHandler` already scope by `stacks`.

### Proof of Concept
1. Shipit is configured with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md` multi-org config).
2. Attacker legitimately administers the GitHub App installation for `org-a` and thus knows `org-a`'s `webhook_secret`.
3. Attacker learns the SHA of a real commit in `org-b/some-repo` (e.g. from GitHub's public commit history).
4. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, a payload whose `repository.owner.login` is `org-a` (so `verify_signature` selects and matches `org-a`'s secret) but whose `sha`/`state`/`context` target the `org-b` commit, signed with `org-a`'s secret.
5. `WebhooksController#verify_signature` succeeds (verified against `org-a`). `StatusHandler#process` runs `Commit.where(sha: params.sha)` and writes a forged `success` status onto the `org-b` commit, with no check that `org-b` was ever authenticated.

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

**File:** docs/setup.md (L181-209)
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
