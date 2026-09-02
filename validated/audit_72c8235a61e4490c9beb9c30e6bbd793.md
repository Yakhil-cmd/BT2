### Title
Webhook signature is verified against the organization in `repository.owner.login`, but handlers act on the repository named in `repository.full_name` — allowing cross-organization stack takeover ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to verify a webhook against using `repository.owner.login` from the **unverified** JSON body, but the handlers that actually act on the payload (e.g. `PushHandler`) resolve the target `Stack` using the different field `repository.full_name`. Because nothing binds these two fields together, a webhook that is cryptographically valid for organization A can be crafted to target a stack belonging to organization B.

### Finding Description
In `WebhooksController#verify_signature`, the organization used to look up the GitHub App config (and thus the `webhook_secret` used for HMAC verification) is taken straight from the request body before any authenticity check: [1](#0-0) [2](#0-1) 

Once `verified` is true, the entire raw payload is forwarded unchanged to the registered handlers: [3](#0-2) 

`Shipit::Webhooks::Handlers::Handler` resolves the `Stack`/`Repository` to operate on from a **different** field of the same payload — `repository.full_name` — not `repository.owner.login`: [4](#0-3) [5](#0-4) 

`PushHandler` then uses that repository's stacks and drives `sync_github`, which reconciles the stack's known commits/HEAD with GitHub, and can feed continuous deployment: [6](#0-5) 

Because Shipit is designed to serve multiple GitHub organizations from one instance (each with its own `webhook_secret`/App), as shown in the sample multi-org secrets file: [7](#0-6) 

...an attacker who legitimately administers one configured organization ("OrgTwo") knows that organization's own `webhook_secret`. They can sign a payload with that known secret while setting `repository.owner.login` to their own org (so `verify_signature` picks their own org's app/secret and the signature checks out) and `repository.full_name` to `victim-org/victim-repo` (so the handler operates on the victim's stack). The binding broken is:

`organization authenticated by verify_signature (repository.owner.login)` ≠ `repository whose stack is written by the handler (repository.full_name)`

### Impact Explanation
An attacker who controls webhook credentials for any one organization configured on a shared Shipit instance can forge webhooks that Shipit treats as verified GitHub traffic for an unrelated organization's repository. Via `PushHandler` this can force `Stack#sync_github` to run against a victim stack at an attacker-chosen time; on stacks with `continuous_deployment: true` this can trigger an unauthorized deploy of the victim's stack — matching the "unauthorized deploy" Critical-severity criterion. Other handlers keyed the same way (`StatusHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`) are similarly reachable, allowing forged commit statuses/merge-queue side effects on repositories the attacker has no access to.

### Likelihood Explanation
This requires the attacker to control (or know) the `webhook_secret` for at least one organization configured on the same Shipit instance — realistic in shared/multi-tenant Shipit deployments where several orgs (including less-trusted ones) are onboarded, since org admins provision their own GitHub App/webhook secret. No access to the victim org, its GitHub App, or a Shipit `ApiClient` token is required, satisfying the "unprivileged attacker" bar.

### Recommendation
Bind webhook verification to the same repository identity the handlers act on: derive the organization used for the App/secret lookup from `repository.full_name` (or verify that `repository.owner.login` matches the owner segment of `repository.full_name`) before dispatching to handlers, rejecting mismatches with 422.

### Proof of Concept
1. Attacker is the admin of "OrgTwo", configured in Shipit with its own `webhook_secret` (known to the attacker).
2. Attacker crafts a push payload:
```json
{
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<sha_on_github>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgTwo_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "OrgTwo")` and successfully verifies the signature using OrgTwo's own secret.
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — a stack the attacker has no legitimate access to — potentially cascading into an unauthorized deploy if continuous deployment is enabled.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
