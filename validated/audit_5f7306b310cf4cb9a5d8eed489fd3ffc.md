### Title
Cross-repository CI status forgery via unscoped commit lookup in `StatusHandler` breaks the org-authenticated-vs-repository-written binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against using only the `repository.owner.login` (or `organization.login`) field of the inbound JSON payload, while the actual event-handling logic for `status` events (`StatusHandler`) looks up the target `Commit` purely by SHA across the *entire* database with no scoping to the repository/organization whose secret validated the request. This breaks the binding "organization authenticated == repository/stack that gets written," allowing an operator of any one configured GitHub organization/app in a multi-org Shipit install to forge a CI status for a commit belonging to a completely different organization's stack.

### Finding Description
`WebhooksController#verify_signature` picks which `GithubApp`/webhook secret to use for HMAC verification based on a field taken directly from the untrusted, attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

Shipit supports configuring multiple independent GitHub App installations, one per organization, each with its own `webhook_secret` known to whoever configured that org's GitHub App: [3](#0-2) 

Once the signature is verified against the org identified by `repository.owner.login`, the raw parsed JSON is dispatched to handlers with no further consistency check tying the verified org to the rest of the payload: [4](#0-3) 

Most handlers scope their side effects to the repository named in `payload.dig('repository', 'full_name')` via the base `Handler#stacks`/`#repository_name` helpers: [5](#0-4) 

However, `StatusHandler#process` does **not** scope its lookup to the repository at all — it queries `Commit.where(sha: params.sha)` globally, across every stack/repository in the Shipit instance, and immediately persists a status object built from attacker-controlled fields (`state`, `description`, `target_url`, `context`): [6](#0-5) 

Because the webhook signature only proves "this payload was signed with OrgA's webhook_secret," and OrgA's own webhook_secret is known to whoever configured OrgA's GitHub App, an attacker in that role can send an arbitrary, self-crafted `status` event body (not a real GitHub-issued event) whose `sha` field matches a commit belonging to OrgB's stack — a completely different, unrelated organization/repository configured in the same Shipit instance. The signature check passes (it only validates the byte stream against OrgA's secret), and `StatusHandler` will happily attach a forged status to OrgB's commit since it never checks which repository/organization the SHA belongs to.

This directly parallels the report's core bug class: a value (the "price"/authorization context) is established once, but a different, unguarded code path is later allowed to act using inconsistent/stale/unverified data for the same identifier — here, "the org whose secret validated the request" vs. "the repository/commit the handler actually writes to."

### Impact Explanation
A forged CI status can flip `Commit#success?`/`Commit#deployable?` state on another organization's stack: [7](#0-6) 

and can trigger continuous delivery for that foreign stack once the commit is marked deployable: [8](#0-7) 

This can cause an unauthorized deploy to proceed on a stack the attacker does not administer, satisfying the "unauthorized deploy" Critical-impact criterion, by forging a passing status on a commit whose CI actually failed or is still pending in the real (foreign) organization.

### Likelihood Explanation
Requires the attacker to be a legitimate administrator/operator of *any one* of the GitHub App installations configured in a multi-organization Shipit deployment (i.e., someone who knows that org's `webhook_secret`, which they themselves set when installing the app) — not a fully unauthenticated internet attacker, and not requiring any Shipit session/API token/repository write access to the *target* org. This is a realistic misuse of a supported, documented configuration (`docs/setup.md` "Using Multiple Github Applications"), and the bug is a straightforward, deterministic logic flaw (no timing/race condition needed), making exploitation reliable once the attacker knows their own org's secret and the target commit SHA (which is discoverable via the target repo's public commit history).

### Recommendation
In `StatusHandler` (and ideally in `Handler` generally), scope the `Commit` lookup to the repository identified in the payload and verify that this repository actually belongs to the organization whose webhook secret validated the request, e.g. `stacks.joins(...).where(commits: { sha: params.sha })` restricted via `Repository.from_github_repo_name(repository_name)`, and reject the webhook if `repository.owner.login`/`organization.login` does not match the repository's actual owning organization on file in Shipit.

### Proof of Concept
1. Shipit is configured with two independent GitHub App installations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org example).
2. The attacker administers `OrgA`'s GitHub App and therefore knows `OrgA`'s `webhook_secret`.
3. The attacker crafts a `status` webhook payload (not from GitHub) referencing a commit SHA belonging to `OrgB/private-repo`'s stack:
   ```json
   {
     "sha": "<sha-of-commit-in-OrgB-stack>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "full_name": "OrgB/private-repo", "owner": { "login": "OrgA" } }
   }
   ```
4. The attacker signs this body with `OrgA`'s known `webhook_secret` and POSTs it to `/github/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `OrgA`'s `GithubApp`, and the HMAC check succeeds because the attacker used the correct (their own) secret.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the `OrgB` commit (no ownership check), then calls `create_status_from_github!(params)`, persisting a forged `success` status for a commit the attacker never had write access to.
7. If `OrgB`'s stack has continuous deployment enabled and this was the last required status, `schedule_continuous_delivery` triggers an unauthorized deploy of `OrgB`'s stack based on the forged status.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-26)
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
