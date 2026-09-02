### Title
Cross-organization webhook forgery via mismatched signature-selection field and repository-resolution field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The DropBox report is about a "verified/consumed" quantity binding breaking apart from the quantity checked at action time. The direct analog in shipit-engine is a binding between **which GitHub organization's webhook secret is used to verify a signature** and **which repository/organization the resulting webhook payload is actually applied against**. These are read from two different, independently attacker-controlled fields of the same unauthenticated-until-verified JSON body, and nothing enforces that they refer to the same tenant.

### Finding Description
`Shipit::WebhooksController#verify_signature` selects the `GithubApp`/secret used for HMAC verification using `repository_owner`, which is read straight out of the untrusted request body: [1](#0-0) [2](#0-1) 

Once the signature check passes, the raw body is parsed and dispatched to handlers, e.g. `Shipit::Webhooks::Handlers::PushHandler`, which resolves the **stack/repository to act on** using a *different* field of the same body: `payload.dig('repository', 'full_name')` via the shared `Handler#stacks` helper. [3](#0-2) [4](#0-3) 

The equality that must hold for the signature check to mean anything is:

`organization used to fetch the webhook_secret (repository.owner.login / organization.login)` == `organization that owns the repository actually written to (repository.full_name)`

Nothing in `verify_signature`, `PushHandler`, or `Handler#stacks` enforces this equality. Because Shipit supports multiple independently-configured GitHub orgs/apps in the same instance (`Shipit.github(organization:)`, see `test/dummy/config/secrets_double_github_app.yml` showing `OrgOne`/`OrgTwo` both configured with their own `webhook_secret`), an attacker who legitimately controls one configured org's GitHub App (and therefore genuinely knows that org's `webhook_secret`) can craft a body where:
- `repository.owner.login` = their own org (so `verify_signature` looks up *their own* known secret and the HMAC they compute with it validates), while
- `repository.full_name` = `"victim-org/victim-repo"` (a different, unrelated tenant's repository that also has stacks configured on the same Shipit instance).

`lib/shipit/github_app.rb#verify_webhook_signature` only checks that the HMAC matches the secret for the organization named in the (attacker-chosen) `repository_owner` field — it has no concept of, or dependency on, `repository.full_name`: [5](#0-4) 

The signature therefore "authenticates" one organization while the handler acts on a repository belonging to a completely different one — exactly the confused-deputy pattern called out in the rules ("an organization that authenticated versus the repository that is written").

### Impact Explanation
Because `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on stacks resolved from the forged `repository.full_name`, an attacker who is a legitimate (but low-privilege, single-org) tenant of a shared/multi-org Shipit deployment can trigger GitHub-sync/continuous-delivery side effects (e.g. forcing an unexpected `expected_head_sha`, or firing sync/refresh flows) against another tenant's stack that they have no authorization over, purely by forging the `repository`/`organization` object fields in a webhook body while signing with their own legitimately-known secret. This is an unauthorized cross-repository action triggered through the webhook trust boundary, matching the "cross-repository writes / unauthorized deploy-adjacent action" impact bucket.

### Likelihood Explanation
Exploitability strictly requires the attacker to be one of the organizations actually configured (with a real `webhook_secret`) on the target Shipit instance — i.e. this is only reachable on multi-tenant/shared Shipit deployments where more than one organization's GitHub App is registered, and the attacker is one such tenant. In that (documented, supported — see `docs/setup.md` and the double-github-app test fixtures) configuration, no special privilege beyond "control one configured org" is needed; the attacker does not need write access to the victim repository, a Shipit session, or an `ApiClient` token.

### Recommendation
Bind the two fields together before dispatching to handlers: verify that `repository.owner.login` (or `organization.login`) matches the same organization implied by `repository.full_name`'s owner segment before selecting handlers/acting, or resolve the target `Stack`/`Repository` via the organization whose secret actually verified the signature rather than via an independently-controlled body field.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgOne` and `OrgTwo` (as in `test/dummy/config/secrets_double_github_app.yml`), each with its own real `webhook_secret`, and each with at least one stack tracking a repository (`OrgOne/repo-a`, `OrgTwo/repo-b`).
2. As the operator/attacker who legitimately controls `OrgOne`'s GitHub App and therefore knows `OrgOne`'s `webhook_secret`, build a push payload body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": { "full_name": "OrgTwo/repo-b", "owner": { "login": "OrgOne" } }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgOne_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgOne")` (from `repository.owner.login`) and successfully verifies the signature against the attacker's own known secret.
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgTwo/repo-b")` and invokes `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `OrgTwo`'s stack — an action the attacker was never authorized to trigger.

Note: I was not able to execute this PoC in a running instance (no filesystem/terminal access here); the trace above is derived directly from reading `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/push_handler.rb`, and `lib/shipit/github_app.rb`, and from the multi-org configuration pattern present in `test/dummy/config/secrets_double_github_app.yml`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
