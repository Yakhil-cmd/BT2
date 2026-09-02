### Title
Webhook signature is verified against an organization derived from `repository.owner.login`, while the stack that is actually mutated is selected from the independent, unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks which GitHub App / webhook secret to validate a delivery against by reading `repository.owner.login` (or `organization.login`) out of the **unauthenticated** JSON body itself, and then HMAC-verifies the raw body against that org's secret. Every downstream handler (`Shipit::Webhooks::Handlers::Handler#stacks`, used by `PushHandler`, `StatusHandler`, pull-request handlers, etc.) instead resolves the target `Repository`/`Stack` using a *different* field of the same body, `repository.full_name`. Because the field used to pick the verifying secret and the field used to pick the object that gets mutated are not the same, and are not cross-checked against each other, an attacker can choose which organization's key protects the request while still writing to a stack that belongs to an entirely different, protected organization.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) [2](#0-1) 

selects the signing organization purely from attacker-supplied JSON (`repository.owner.login` / `organization.login`) before the signature has even been checked, then calls: [3](#0-2) 

`verify_webhook_signature` returns `true` unconditionally when that organization has no `webhook_secret` configured (`return true unless webhook_secret`). This means for any GitHub App/org entry in `secrets.yml` that has no `webhook_secret` set, **any** payload claiming that org as `repository.owner.login` passes verification with no cryptographic check at all.

Meanwhile, every handler resolves what actually gets written using a completely different field: [4](#0-3) 

`repository_name` comes from `payload.dig('repository', 'full_name')`, not from `repository.owner.login`. `PushHandler#process` uses `stacks` (i.e., this `full_name`-derived repository) to trigger `stack.sync_github`: [5](#0-4) 

There is no code path anywhere in the webhook pipeline that checks `repository.owner.login == repository.full_name.split('/').first`. The equality that should hold is:

`organization authenticated (repository.owner.login → github_app secret) == organization whose repository is written (repository.full_name → Repository/Stack)`

but the engine never enforces it. An attacker who knows (or can probe, since `Shipit.github` errors with `Shipit::GithubOrganizationUnknown` for unknown orgs, effectively confirming valid org names) that one configured GitHub App/org has `webhook_secret: null` can send a raw POST to `/webhooks` with:
```json
{
  "repository": { "owner": { "login": "<org-with-no-secret>" }, "full_name": "<victim-org>/<victim-repo>" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
Signature verification succeeds (organization used for verification has no secret), and `PushHandler` then calls `sync_github` on any stack matching `<victim-org>/<victim-repo>`, which is a real, secret-protected repository. The same technique applies to `StatusHandler` (forging a passing CI status via `sha`/`state`) and the `PullRequest::*Handlers` (forging label/opened/closed/reopened events), all of which resolve their target strictly by `repository.full_name` while the org used for auth is `repository.owner.login`/`organization.login`.

### Impact Explanation
This breaks the deployment-trust binding between "the organization whose credentials authorize this webhook" and "the repository/stack that is actually written," matching the High-impact class of "escalation ... unauthenticated read/write of stack state" — but going further: forged `push` events can trigger `GithubSyncJob`/`stack.sync_github` against a protected repository's stack, and forged `status` events can inject fabricated commit statuses that CI/merge-queue logic (`ci.require`, continuous deployment gating) relies on to permit deploys. In installations with `continuous_deployment: true` and CI status requirements, a forged "success" status combined with a forged push can be used to push the deploy pipeline toward shipping an attacker-influenced revision — i.e., contributing to an unauthorized deploy, which is explicitly in the Critical impact bucket ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitability depends entirely on host configuration: it requires (a) a multi-tenant Shipit install with more than one GitHub App/org entry in `secrets.yml`, and (b) at least one of those orgs having `webhook_secret` unset while another org's repositories are the actual target. This is a plausible real-world configuration (e.g., organizations onboarded before webhook secrets were mandated, or a test/staging org intentionally left without a secret) but is not a universal default — Shipit's setup docs encourage configuring `webhook_secret` for every org. Given the conditional nature, likelihood is Medium, but no privileged credential, session, or API token is required — only knowledge of one org name that lacks a webhook secret, which can be probed via the `Shipit::GithubOrganizationUnknown` error path (returns 422 with a distinguishable log/response) versus a signature failure (also 422) — timing/response differences would need confirmation, but the underlying architectural bypass is unconditional once such an org exists.

### Recommendation
1. Verify the webhook signature using the organization derived from `repository.full_name` (or the same field the handlers use), not a separately-read `repository.owner.login`/`organization.login`.
2. Do not allow `verify_webhook_signature` to silently pass when `webhook_secret` is blank in multi-org configurations; require every configured GitHub App/org to have a webhook secret, or fail closed when it's missing rather than returning `true`.
3. After signature verification, assert that the organization used to authenticate the request matches the owner segment of `repository.full_name` before handlers are invoked, rejecting the request otherwise.

### Proof of Concept
Given a `secrets.yml` with two orgs configured, e.g.:
```yaml
github:
  victim-org:
    webhook_secret: "s3cr3t"
    ...
  empty-org:
    webhook_secret: null
    ...
```
An attacker (no credentials) sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000

{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "empty-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
`repository_owner` resolves to `empty-org`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` regardless of the bogus `X-Hub-Signature`. `PushHandler` then resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the real, secret-protected `victim-org` stack — a forged event fully bypassing that org's webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
