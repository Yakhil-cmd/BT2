## Analysis Summary

The "transfer vs call" report is a Solidity gas-forwarding issue with no direct analog in this Ruby engine. However, following the required binding categories, I traced the strongest reachable analog: **the field used to select the webhook signature-verification key is not the same field used to determine which data the webhook payload is allowed to mutate.** [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Webhook signature verification is keyed on `repository.owner.login`, but `StatusHandler` matches commits globally by SHA with no repository binding - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against using `repository_owner`, read from the untrusted JSON body (`params.dig('repository','owner','login')` or `organization.login`). That value only proves the request was signed by *some* configured organization's secret — it says nothing about which repository or stack the rest of the payload is allowed to affect. `Shipit::Webhooks::Handlers::StatusHandler#process` then does `Commit.where(sha: params.sha)`, a **global, cross-stack, cross-repository** lookup, and calls `commit.create_status_from_github!(params)` on every match, ignoring `repository.full_name` entirely (unlike `Handler#stacks`, which other handlers use).

### Finding Description
The trust binding that should hold is: *organization whose secret authenticated the request* == *repository/stack the payload is permitted to mutate*. This binding is broken in two independent ways:

1. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for the resolved organization [4](#0-3) . `webhook_secret` is documented as optional [5](#0-4) , and the multi-org config format explicitly supports several organizations, each with its own `webhook_secret` key [6](#0-5) . Any operator running multi-org Shipit with even one org lacking a secret (a documented, supported configuration) makes `/webhooks` accept **arbitrary unsigned JSON** as long as `repository.owner.login` in the body names that unsecured org.
2. Once past that check, `StatusHandler` never re-derives or checks which repository/stack the SHA belongs to — it queries `Commit.where(sha: params.sha)` across the **entire database** [3](#0-2) , unlike `PushHandler`/`Handler#stacks`, which correctly scope by `repository.full_name` [7](#0-6) , [8](#0-7) .

The result: an attacker only needs to name an unsecured org as `repository.owner.login` to pass `verify_signature`, then set `params.sha` to any commit SHA that happens to exist in *any other* organization's/stack's history in the same Shipit install, and inject a fabricated CI status (`state: "success"`, etc.) for it.

### Impact Explanation
`Commit#create_status_from_github!` feeds into `Commit#status`, `#deployable?`, and `#schedule_continuous_delivery` [9](#0-8) , [10](#0-9) . A commit only becomes `deployable?` when `success? && !blocked?` (or CI is ignored), and `schedule_continuous_delivery` enqueues `ContinuousDeliveryJob` once a commit is `deployable?` and the stack has `continuous_deployment?` enabled. By forging a "success" status for a target commit belonging to a *different* org/stack than the one whose (missing) secret was used to pass verification, an unprivileged remote attacker can flip a commit's blocking/CI gate and trigger an automatic, unauthorized deploy on a stack they have no legitimate relationship to — satisfying the Critical bar ("an unauthorized deploy").

### Likelihood Explanation
Requires: (a) the Shipit instance is configured for multiple GitHub organizations (documented, supported setup) with at least one org lacking `webhook_secret` (also documented as optional), and (b) the attacker knows/guesses a target commit SHA in another stack (SHAs are often public via GitHub, PR/commit links, or Shipit's own UI). Both preconditions are realistic in shared/multi-tenant Shipit deployments and require no privileged credentials, no `ApiClient` token, and no GitHub write access to the target repo — only knowledge of one configured-but-unsecured org name and a target SHA.

### Recommendation
- Scope `StatusHandler` (and any other handler that doesn't already do so) to the repository named in the payload, mirroring `Handler#stacks`/`repository_name`, and cross-check that `repository_name`'s owner matches the `repository_owner` that was used for signature verification.
- Do not allow `verify_webhook_signature` to short-circuit to `true` when `webhook_secret` is unset; require an explicit `Shipit.disable_webhook_authentication`-style opt-in per organization instead of silently trusting unsigned payloads for that org while other orgs remain protected.
- Reject events whose `repository.owner.login` (used for auth) doesn't match `repository.full_name`'s owner (used for data lookup).

### Proof of Concept
1. Configure Shipit with two orgs in `config/secrets.yml`: `orgA` (no `webhook_secret` set) and `orgB` (properly configured, has a stack with commit `SHA_X` currently blocked/pending on CI, `continuous_deployment: true`).
2. POST to `/webhooks` with header `X-Github-Event: status` and no valid `X-Hub-Signature`, body:
```json
{
  "sha": "SHA_X",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgA/whatever" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "orgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of signature.
4. `StatusHandler#process` runs `Commit.where(sha: "SHA_X")`, matches the commit in `orgB`'s stack (unrelated to `orgA`), and calls `create_status_from_github!`, marking it `success`.
5. If that commit is now `deployable?` and the stack is `continuous_deployment?`, `ContinuousDeliveryJob` is scheduled, producing an unauthorized deploy on `orgB`'s stack — triggered entirely by an attacker who only controls `orgA`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** docs/setup.md (L188-209)
```markdown
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/commit.rb (L219-229)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

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
