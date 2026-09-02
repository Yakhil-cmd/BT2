### Title
Webhook signature verification is keyed to an attacker-controlled organization field that is decoupled from the repository/commit actually written by the handler - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the request against using `repository_owner`, a value read directly out of the unauthenticated JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). The event handlers that actually mutate state (e.g. `StatusHandler`) look up the target `Commit`/`Stack` using a *different* field from the same body (`sha`, and in other handlers `repository.full_name`), with no re-check that it belongs to the organization whose secret was used for verification. If any configured GitHub App/organization in `secrets.yml` has a blank `webhook_secret` (a documented, supported configuration - see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`), `verify_webhook_signature` returns `true` unconditionally, and an attacker can forge events that write to commits/stacks belonging to *any other* organization on the same Shipit instance.

### Finding Description
`verify_signature` chooses the app/secret to check against based on attacker-supplied JSON, not on any pre-authenticated identity: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` treats a blank/`nil` `webhook_secret` as "no verification required" rather than rejecting the request: [3](#0-2) 

Multiple documented deployment configurations legitimately leave `webhook_secret` blank for one or more configured orgs while other orgs (with real production stacks) do have a secret configured: [4](#0-3) [5](#0-4) 

Once the request passes `verify_signature` (bypassed via the blank-secret org), `create` dispatches the *entire attacker-controlled payload* to the registered handlers for the event type: [6](#0-5) 

`StatusHandler` looks up the target purely by `sha`, with **no scoping at all** to the repository/organization that was used for signature verification (unlike `Handler#stacks`, which at least scopes by `repository.full_name`, `StatusHandler` doesn't even use that scoping): [7](#0-6) 

`commit.create_status_from_github!(params)` writes the attacker-supplied `state`/`context`/`description`/`target_url` directly as a `Status` record with no independent verification against the GitHub API: [8](#0-7) 

This exactly matches the requested analog class: the entity that gets *authenticated* (the organization whose `webhook_secret` is used, derived from `repository.owner.login`/`organization.login`) is not bound to the entity that gets *written* (the `Commit`/`Stack` located purely by `sha`, which can belong to a completely different repository/organization in the same Shipit instance). The equality that should hold - `organization authenticated == organization owning the commit/stack written` - is not enforced anywhere in the request path.

### Impact Explanation
A forged `status` webhook that marks a commit as `success` for a required CI context flips `Commit#deployable?` to true: [9](#0-8) 

Because `Status#schedule_continuous_delivery` and `enable_ci_on_stack` fire as `after_create`/`after_commit` callbacks, a forged success status on a commit belonging to a *different, unrelated* stack can push that stack into a state where `Stack#deployable?` becomes true and continuous delivery is scheduled: [10](#0-9) [11](#0-10) 

This can produce an **unauthorized deploy** of a stack that the attacker has no legitimate access to, satisfying the "High"/"Critical" impact bar (unauthorized deploy via forged CI status, achieved without any Shipit session, API token, or GitHub write access to the target repository - only knowledge that some other org on the instance has a blank webhook secret).

### Likelihood Explanation
Likelihood depends on operational configuration: it requires that at least one GitHub App/org registered on the Shipit instance has a blank `webhook_secret` while other orgs host stacks the attacker wants to influence. This is not a hypothetical edge case - it is exactly the configuration shown in the project's own sample and test fixtures (`secrets.development.shopify.yml`, `secrets_double_github_app.yml`), and is plausible in real multi-org deployments where a lower-trust or freshly-added org hasn't had its webhook secret set yet. No credentials, GitHub write access, or Shipit session are required - only an unauthenticated POST to the public `/webhooks` endpoint.

### Recommendation
- Never treat an absent/blank `webhook_secret` as "skip verification"; require an explicit signature check for every configured organization, and reject the request if no secret is configured (or make the secret mandatory at boot for any registered org).
- Bind the outcome of `verify_signature` to the specific repository/stack being written: after locating the target `Commit`/`Stack` in each handler, verify that its `Repository`/organization matches the organization whose secret validated the signature, and reject the event otherwise.
- In `StatusHandler` (and any other handler that resolves state purely by an ID like `sha`), scope the lookup to the verified repository (`repository.full_name`) rather than a global `Commit.where(sha:)` scan, consistent with the pattern already used in `Handler#stacks`.

### Proof of Concept
1. Deploy a Shipit instance configured with two GitHub orgs, `OrgA` (has stacks/commits attacker wants to influence, `webhook_secret` set) and `OrgB` (also connected, `webhook_secret` left blank - as shown to be a supported configuration in `config/secrets.development.shopify.yml`).
2. Attacker obtains the sha of an undeployed/required-CI-pending commit belonging to a stack under `OrgA` (commit shas are often public, e.g. visible on GitHub or the Shipit UI).
3. Attacker sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything

{
  "sha": "<targeted commit sha under OrgA>",
  "state": "success",
  "context": "<required CI context configured for that stack, e.g. ci/circleci>",
  "organization": { "login": "OrgB" }
}
```
4. `verify_signature` resolves `repository_owner` to `OrgB` (no `repository` key present, falls back to `organization.login`), looks up `Shipit.github(organization: 'OrgB')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (bogus) `X-Hub-Signature` header.
5. `StatusHandler.call(params)` runs `Commit.where(sha: params.sha)` - finds the commit under `OrgA` (no relationship to `OrgB` is checked) and calls `create_status_from_github!`, creating a forged `success` status.
6. If this satisfies the stack's required CI contexts, `Commit#deployable?`/`Stack#deployable?` become true and continuous delivery (if enabled) schedules an unauthorized deploy of `OrgA`'s stack.

Note: I was unable to fully inspect `Commit#create_status_from_github!` and `Deploy#schedule_continuous_delivery` bodies within the available index (search results returned matches but not full file contents for `app/models/shipit/commit.rb` beyond line 270 and `app/models/shipit/deploy.rb`); the causal chain from "forged Status created" to "deploy scheduled" is inferred from `Status#schedule_continuous_delivery`'s callback wiring and `Stack#deployable?`/`Commit#deployable?` definitions cited above, and from the `stack_test.rb` continuous-delivery tests. A Devin session with full repository access would be needed to confirm the exact deploy-triggering code path end-to-end.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-23)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/stack.rb (L376-378)
```ruby
    def deployable?
      !locked? && !active_task? && !awaiting_provision? && deployment_checks_passed?
    end
```
