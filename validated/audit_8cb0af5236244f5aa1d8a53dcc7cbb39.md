### Title
Webhook signature verification is scoped by an attacker-controlled organization field, letting a missing per-org `webhook_secret` bypass authentication for events acting on repositories/stacks belonging to *other* organizations - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects **which** GitHub App/organization secret to validate a webhook against using a field read straight out of the *unverified* JSON body, and if that particular organization has no `webhook_secret` configured, verification is unconditionally skipped. Because the resulting `create` action dispatches work (syncing commits, recording commit statuses, etc.) based on `repository.full_name` from the very same payload — with no re-check that this repository actually belongs to the organization used for the (skipped) signature check — an attacker can forge a completely unsigned webhook that is accepted as if it came from GitHub, and have it acted on for any repository/stack tracked by the Shipit instance, not just the org lacking a secret.

### Finding Description
`verify_signature` resolves the GitHub App to check against from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

`repository_owner` is taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`), i.e. directly from the raw, not-yet-verified request body. That value is used to pick a `GitHubApp` instance via `Shipit.github(organization:)`, whose `verify_webhook_signature` is: [3](#0-2) 

Note `return true unless webhook_secret` — if the org resolved from the attacker-chosen `repository.owner.login` has **no** `webhook_secret` configured (documented as optional per org, see `docs/setup.md` "Using Multiple Github Applications" and the example configs `test/dummy/config/secrets_double_github_app.yml`, `config/secrets.development.shopify.yml`), the whole signature check is bypassed and `verified` is `true` for *any* body.

Once past this before_action, `create` re-parses the same raw body and dispatches to handlers using a *different* field from the same payload — `repository.full_name` — with no cross-check against the organization that was used (or not used) for authentication: [4](#0-3) [5](#0-4) [6](#0-5) 

This is the same class of bug as the reported ERC-20 issue: code assumes a benign default ("no secret configured" ⇒ treat as verified) without checking that the *thing it authorizes* (the organization named in the payload) is the same as the *thing it acts on* (the repository/stack named in the same payload). The equality the code implicitly (and wrongly) assumes is:

`organization used to select webhook_secret (attacker-controlled, unauthenticated at that point) == organization owning the repository that PushHandler/StatusHandler/CheckSuiteHandler/etc. subsequently act on`

Before the attack: only a genuine GitHub webhook, HMAC-signed with the org-specific secret, can reach `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` for a given tracked repository.
After the attack: any anonymous, unauthenticated POST to `/webhooks` naming an organization with a blank `webhook_secret` in `repository.owner.login`, but naming a *different*, sensitive repository in `repository.full_name`, is treated as fully verified and dispatched normally.

### Impact Explanation
Handlers triggered this way operate on arbitrary tracked repositories/stacks:
- `PushHandler` ( [6](#0-5) ) calls `stack.sync_github(expected_head_sha:)` for any stack matching the forged `repository.full_name`/branch, letting an attacker force a resync against an arbitrary head SHA.
- The `status` handler and `check_suite` handler record commit statuses/check results for arbitrary SHAs on tracked stacks. Combined with Shipit's continuous-delivery feature (`app/jobs/shipit/continuous_delivery_job.rb`, `app/controllers/shipit/continuous_delivery_schedules_controller.rb`), which auto-deploys commits once required statuses/checks turn green, an attacker could forge "success" statuses for a malicious commit and trigger an **unauthorized automatic deploy** — squarely in the Critical impact bucket ("an unauthorized deploy, rollback or merge").
- `membership`/`pull_request` handlers similarly act on data taken from the same unverifiable payload.

This requires no Shipit session, no `ApiClient` token, and no privileged GitHub role — only knowledge (or guessing) that a multi-org Shipit deployment has at least one configured organization with a blank `webhook_secret`, which the setup docs explicitly present as an acceptable ("optional") configuration.

### Likelihood Explanation
`docs/setup.md` explicitly documents the multi-organization configuration schema and marks `webhook_secret` as optional for each org; the shipped example/test fixtures (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`) show multiple orgs configured with `webhook_secret: # nil`. Any deployment following this documented pattern with even one org lacking a secret is exposed, and exploitation requires only a single crafted, unauthenticated HTTP POST — no credentials, sessions, or timing races.

### Recommendation
- Do not derive the verifying organization from unauthenticated request data used later to look up which repository to act on; instead, verify the signature using every organization's configured secret (or explicitly reject payloads when the resolved organization has no secret configured) and then re-validate that `repository.full_name`'s owner matches the organization that successfully verified the payload.
- Treat a missing/blank `webhook_secret` as "signature verification cannot succeed for this org" (fail closed) rather than "skip verification" (`return true unless webhook_secret`).
- Add an explicit check in `WebhooksController#create` (or in `Handler`) that the repository referenced in the payload belongs to the organization that was actually authenticated for that request, rejecting mismatches.

### Proof of Concept
1. Deploy Shipit with the documented multi-org GitHub App configuration (`docs/setup.md`, "Using Multiple Github Applications"), where organization `OrgWithoutSecret` has `webhook_secret` left blank, while `OrgTarget/critical-repo` is a tracked Shipit stack with a properly configured secret and continuous-delivery enabled.
2. As an anonymous attacker, POST to `/webhooks` with header `X-Github-Event: push` (no `X-Hub-Signature` needed) and a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-that-exists-in-OrgTarget/critical-repo>",
  "repository": {
    "full_name": "OrgTarget/critical-repo",
    "owner": { "login": "OrgWithoutSecret" }
  }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgWithoutSecret")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request passes verification.
4. `WebhooksController#create` dispatches to `PushHandler`, which looks up stacks for `OrgTarget/critical-repo` (unrelated to `OrgWithoutSecret`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, an action normally gated by a valid GitHub-signed webhook for `OrgTarget`.

*Uncertainty:* I could not fully trace whether `sync_github`/continuous-delivery auto-deploy would trigger immediately from a forged `status`/`check_suite` payload in every configuration (this depends on stack-specific CD schedule/settings in `app/models/shipit/stack.rb` and `app/jobs/shipit/continuous_delivery_job.rb`, which I did not have time to fully inspect in this pass); the core authentication-bypass/cross-organization-dispatch flaw in `verify_signature` and `repository_owner`, however, is directly confirmed by the cited code.

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
