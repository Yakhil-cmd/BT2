### Title
Webhook signature is verified against an organization chosen from an unauthenticated payload field, but writes are keyed on an unrelated field (repository `full_name` / bare commit `sha`) — ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App/organization secret to check the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted, unauthenticated JSON body, and then verifies the signature using that org's `webhook_secret`. [1](#0-0) [2](#0-1) [3](#0-2) 

Every downstream event handler, however, resolves the repository/commit that gets *written to* from a completely different, independent field of the same body — `repository.full_name` in the generic `Handler` base class, or a bare commit `sha` with no repository scoping at all in `StatusHandler`: [4](#0-3) [5](#0-4) 

Because GitHub itself always keeps `repository.owner.login` and `repository.full_name` consistent, this split never matters for legitimate traffic. But Shipit's own signature check trusts a self-reported, unauthenticated field (`repository.owner.login`) to pick the *verification key*, while never re-checking that the same request's *write target* (`full_name`, or the naked `sha` in `StatusHandler`) actually belongs to that verified organization. This is exactly the report's bug class: one field is used to authorize/authenticate ("amount owed with `false`" ≈ "org used for the signature"), while a materially different field is what's actually acted on ("amount transferred" ≈ "repository/commit written").

### Finding Description
`Shipit.github(organization: repository_owner)` picks a per-organization `GitHubApp` config (each with its own, independently-set `webhook_secret`), and `GitHubApp#verify_webhook_signature` explicitly **skips verification entirely** when that organization's secret is unset — a documented, supported configuration (`docs/setup.md` calls the webhook secret "optional"): [6](#0-5) [7](#0-6) 

In a multi-org deployment (explicitly supported and documented in `config/secrets.development.example.yml`), if *any one* configured organization has no `webhook_secret`, an attacker can craft an arbitrary JSON body, set `repository.owner.login` (or `organization.login`) to that unprotected org so `verify_signature` short-circuits to `true`, and set the actually-acted-upon field to point at a *different*, unrelated, fully-secured repository/commit:

- `PushHandler`/`CheckSuiteHandler` resolve stacks via `Handler#repository_name` → `payload.dig('repository', 'full_name')`, which is never cross-checked against `repository.owner.login` used for verification. [8](#0-7) [9](#0-8) 
- `StatusHandler#process` is worse: it does not consult `repository`/`stacks` at all, it directly matches `Commit.where(sha: params.sha)` — a globally-scoped lookup — and calls `commit.create_status_from_github!(params)` to persist attacker-supplied `state`, `description`, `target_url`, and `context` onto that commit. [10](#0-9) 

The equality that should hold is: `organization whose secret authenticated the request == organization owning the repository/commit that gets mutated`. Shipit's code breaks this: the first side is derived from `repository.owner.login`/`organization.login` (attacker-controlled, and trivially satisfiable if any configured org has no secret), while the second side is derived from `repository.full_name` or a bare `sha`, neither of which is checked against the first.

### Impact Explanation
This lets an attacker who can reach `/webhooks` (an unauthenticated, internet-facing endpoint by design) forge a CI `status` (e.g., `state: "success"`) on any commit `sha` tracked by *any* stack in the Shipit instance — including stacks belonging to organizations that have properly configured webhook secrets — as long as one other configured organization in the same deployment has no secret set. Shipit stacks gate merges/auto-deploys and continuous-delivery progression on commit statuses/checks, so forging a green status can be used to push a stack's state toward an unauthorized deploy/merge decision on a repository the attacker never authenticated against. This matches the "unauthorized deploy, rollback, or merge" High-impact category.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured for multiple GitHub organizations (a documented, supported use case), and (2) at least one of those organizations having no `webhook_secret` set (also explicitly documented as optional). Given both are officially supported configurations rather than deviations from documented setup, an unprivileged external attacker only needs network access to the public `/webhooks` endpoint — no `ApiClient` token, no `github_access_token`, and no knowledge of any actual `webhook_secret` is required for the unprotected organization.

### Recommendation
Bind the verified identity to the acted-upon resource instead of trusting independent payload fields:
- After `verify_signature` succeeds, re-derive the acted-upon repository from the *same* field used for verification (`repository.owner.login`) and reject/ignore the event if `repository.full_name`'s owner segment doesn't match.
- In `StatusHandler`, scope `Commit.where(sha: ...)` by the verified repository (via its `Stack`/`Repository`), not by a bare, cross-repository-unique `sha` lookup.
- Consider making `webhook_secret` mandatory per configured organization (removing the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`), or at minimum, refuse to process any event whose target repository resolves to an organization other than the one whose secret validated the signature.

### Proof of Concept
1. Configure Shipit for two organizations: `secure-org` (with `webhook_secret` set) and `open-org` (with `webhook_secret` left blank, as permitted by `docs/setup.md`).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: status` and body:
   ```json
   {
     "repository": { "owner": { "login": "open-org" }, "full_name": "open-org/whatever" },
     "sha": "<sha of a commit belonging to a stack under secure-org>",
     "state": "success",
     "context": "ci/required-check"
   }
   ```
   No `X-Hub-Signature` header is required to pass, because `verify_webhook_signature` returns `true` unconditionally when `open-org`'s `webhook_secret` is blank [11](#0-10) .
3. `WebhooksController#verify_signature` selects `open-org`'s (secret-less) app config based on the payload's `repository.owner.login`, verification trivially "succeeds", and `StatusHandler#process` is invoked [5](#0-4) .
4. `Commit.where(sha: params.sha)` matches the target commit under `secure-org` (global lookup, no repository scoping), and a forged `success` status is written onto it — despite the request never being authenticated by `secure-org`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
