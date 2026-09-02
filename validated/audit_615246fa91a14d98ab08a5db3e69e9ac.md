## Title
Webhook signature scoping is decoupled from the repository being written, allowing forged commit statuses / cross-repository writes when an organization's `webhook_secret` is unset - (File: `app/controllers/shipit/webhooks_controller.rb`)

## Summary
The reported issue asks for a floor value on a config field (`EpochLimit`) so that a permissive/misconfigured setting cannot destroy data the app depends on. The structural analog in this engine is that the field used to select **which secret verifies the request** (`repository.owner.login`) is never the field used to decide **which repository/commit the request is allowed to mutate** (`repository.full_name` or, in `StatusHandler`, nothing at all — just a raw `sha`). When the organization selected by the first field has no `webhook_secret` configured (an explicitly supported, documented configuration), the second field is completely attacker-controlled.

## Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to validate against using only the payload's `repository.owner.login` (or `organization.login`): [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that organization has no configured `webhook_secret`: [3](#0-2) 

`webhook_secret` is documented as optional (`"If you've set a webhook secret during the App creation, you should copy it here."`), and the shipped test/dummy configs set it to `nil`, confirming this is a normal, supported deployment shape rather than an edge case: [4](#0-3) [5](#0-4) 

Once past `verify_signature`, the controller hands the **entire attacker-supplied JSON body** to the registered handlers with no re-validation: [6](#0-5) 

`StatusHandler`, which creates commit statuses, does not scope by repository at all — it matches purely on the attacker-supplied `sha` against every `Commit` row in the entire Shipit instance: [7](#0-6) 

Other handlers (`PushHandler`, the `PullRequest::*` handlers) do scope to a repository, but via `payload.dig('repository', 'full_name')` — a field that was never covered by the signature-selection logic and is not cross-checked against `repository.owner.login`: [8](#0-7) [9](#0-8) 

This is the exact class of binding break called out for this scan: **"an organization that authenticated versus the repository that is written."** The organization used to authenticate the request (`repository.owner.login`, or effectively "no org at all" once `webhook_secret` is nil) is not equal to the repository/commit that ends up mutated (`repository.full_name`, or in `StatusHandler`'s case, any commit sha in any stack).

## Impact Explanation
If any organization configured in the Shipit instance has no `webhook_secret` set (a documented, supported and commonly-seen configuration — confirmed in the shipped test fixtures), an unauthenticated attacker can POST an arbitrary JSON body to `/github/webhooks` with `X-Github-Event: status` and `repository.owner.login` set to that unprotected organization. `verify_signature` passes unconditionally (`return true unless webhook_secret`), and `StatusHandler#process` then applies the attacker's chosen `state`/`context`/`target_url` to **any commit sha in any stack tracked by the instance**, regardless of which org/repo it actually belongs to: [10](#0-9) 

Commit statuses are used by Shipit to gate CI requirements for deploys and the merge queue (`ci.require`/`merge.require` in `shipit.yml`, materialized via `DeploySpec`/`Status::Group`). Forging a "success" status for a commit that hasn't actually passed CI can therefore let an attacker cause an **unauthorized deploy or an unauthorized merge** through the merge queue — this matches the Critical-impact bucket defined for this scan ("an unauthorized deploy, rollback or merge").

The same owner/full_name mismatch also affects `PushHandler` and the `PullRequest::*` handlers in multi-org installations (as demonstrated by `secrets_double_github_app.yml`, which shows Shipit supporting several orgs each with independently nullable secrets): an attacker who can trigger a real, signed webhook against an org with no secret can craft `repository.full_name` to point at a stack belonging to an entirely different, "protected" repository/org, causing cross-repository writes (sync jobs, PR/review-stack archival/unarchival, label-driven provisioning).

## Likelihood Explanation
Reaching this requires only:
1. Knowledge that some organization configured on the target Shipit instance lacks a `webhook_secret` (not enforced by the engine, and shown as a valid/default configuration in the shipped configs and docs).
2. The ability to send an HTTP POST to the public `/github/webhooks` endpoint, which by design accepts unauthenticated requests (it exists specifically to receive GitHub's webhooks and has no session/API-token requirement).

No GitHub App private key, `webhook_secret`, session, or API token is needed — exactly the "unprivileged attacker" scope required by this exercise. The only variable is whether the operator left `webhook_secret` unset for at least one configured organization, which the engine does nothing to prevent, warn about, or require a minimum-strength alternative for (directly paralleling the "no enforced minimum" root cause in the original report).

## Recommendation
- Require (or strongly warn/fail fast on) a non-blank `webhook_secret` for every configured GitHub organization, instead of silently treating a missing secret as "signature verified."
- Cross-validate that `repository.owner.login` (or `organization.login`) matches the owner portion of `repository.full_name` before dispatching to handlers, so the field used to select the verifying secret can never diverge from the field used to select the mutated resource.
- Scope `StatusHandler` (and any other handler that currently does not scope by repository) by repository/stack, not solely by `sha`, so a forged or misrouted payload cannot affect commits belonging to unrelated repositories.

## Proof of Concept
Preconditions: Shipit instance has organization `acme` configured without a `webhook_secret` (default/omitted, as shown in `test/dummy/config/secrets.test.json` and `secrets_double_github_app.yml`), and tracks a stack for `victim-org/victim-repo` whose current HEAD commit sha the attacker knows (visible on GitHub) and which is gated by `ci.require`.

```
POST /github/webhooks HTTP/1.1
X-Github-Event: status
Content-Type: application/json

{
  "sha": "<victim-org/victim-repo HEAD sha>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://ci.example.com/forged",
  "repository": { "owner": { "login": "acme" }, "full_name": "acme/some-other-repo" }
}
```

Because `acme` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally (`app/controllers/shipit/webhooks_controller.rb#L24-L30`, `lib/shipit/github_app.rb#L76-L83`), and `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb#L20-L24`) writes a forged "success" status onto `victim-org/victim-repo`'s commit — a repository that has nothing to do with the `acme` organization used to pass the signature check — potentially unblocking a deploy or merge that was gated on that CI status.

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

**File:** test/dummy/config/secrets.test.json (L7-13)
```json
  "github": {
    "domain": null,
    "app_id": 42,
    "installation_id": 43,
    "bot_login": "shipit[bot]",
    "webhook_secret": null,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S\n73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG\nM0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv\nibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu\npQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s\nGu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1\nu0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM\nTZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b\nqicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og\nqRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI\nRsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b\ngg9PFCkCgYEA+7u8A0l0C ... (truncated)
```

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
```
