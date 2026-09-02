### Title
Webhook signature verification is bound to the payload's `repository.owner.login`, not the `repository.full_name` actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC against using `repository_owner`, itself read out of the *unverified* request body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). But the code path that actually resolves *which repository gets acted on* (`Handler#repository_name` / `Handler#stacks`) reads a different field, `payload.dig('repository', 'full_name')`, which is never cross-checked against the organization whose secret validated the request.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb#verify_signature` does: [1](#0-0) 

It picks `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature`. Crucially, in `lib/shipit/github_app.rb`: [2](#0-1) 

`verify_webhook_signature` unconditionally returns `true` when that organization's `webhook_secret` is blank (`return true unless webhook_secret`). Shipit's own documentation explicitly shows `webhook_secret: # nil` as a supported, blank configuration for any org in a multi-org deployment (`config/secrets.development.shopify.yml`, `docs/setup.md` "Using Multiple Github Applications" section, `test/dummy/config/secrets_double_github_app.yml`).

Meanwhile, once the event is dispatched, `Shipit::Webhooks::Handlers::Handler#repository_name` and `#stacks` resolve the *actual* target of the action from a completely different, unauthenticated field: [3](#0-2) 

and `PushHandler#process` uses that repository's stacks to trigger `stack.sync_github(expected_head_sha:)`: [4](#0-3) 

The binding that should hold is: `organization authenticated by verify_signature == organization owning the repository written by the handler`. Instead, the code only checks `organization named in repository.owner.login (used to pick verification key) == some org configured in Shipit.github`, and then separately trusts `repository.full_name` (a distinct, sibling field of the same untrusted JSON body) to select the repository to sync/build/deploy — with no requirement that the two fields agree.

In a single-org deployment this gap is latent, because there is only one `webhook_secret`/org and both fields necessarily describe the same tenant. It becomes exploitable exactly in the documented multi-org configuration (`Shipit.github(organization: X)` with a hash of orgs, each with its own possibly-blank `webhook_secret`, as shown in `docs/setup.md#Using Multiple Github Applications`). Any org in that hash configured without a `webhook_secret` (a supported, documented state) causes `verify_webhook_signature` to accept **any** unsigned/forged request whose `repository.owner.login`/`organization.login` names that org — regardless of what `repository.full_name` inside the same forged JSON body claims. An unprivileged attacker with no webhook secret, no `ApiClient` token, and no GitHub credentials can therefore POST a crafted `push`/`pull_request`/`status`/`check_suite` payload where:
- `repository.owner.login = "<org-with-no-webhook_secret>"` (passes `verify_signature` trivially), while
- `repository.full_name = "<any-other-configured-org>/<any-repo>"` (used by `Handler#stacks` to pick the real target).

This decouples "who GitHub says sent this" from "what Shipit acts on," breaking the trust binding the engine relies on to accept unauthenticated webhooks only for the repositories owned by the authenticating installation.

### Impact Explanation
This allows cross-repository, cross-organization forged events against any stack hosted on the same Shipit instance, as long as one configured GitHub App/org in the multi-org config has no `webhook_secret` set. Concretely, a forged `push` event can invoke `Stack#sync_github` on stacks belonging to a *different* organization than the one whose (absent) secret satisfied `verify_signature`, and — for stacks with `continuous_deployment` enabled — syncing new/attacker-asserted commit SHAs can drive deploy triggering logic downstream. Other handlers (`membership`, `pull_request`, `check_suite`, `status`) are reachable the same way, letting an attacker manipulate commit statuses, merge-queue state, or team/user membership records for repositories they do not control. This crosses the "cross-repository writes" / "unauthorized deploy" impact bar without requiring any Shipit session, `ApiClient` token, or GitHub credential.

### Likelihood Explanation
Requires a specific but documented and supported configuration: a multi-org GitHub App setup (`docs/setup.md`) where at least one configured organization has an empty `webhook_secret` (explicitly shown as a valid `# nil` value in `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`). Given that Shipit's own example configs model this as normal, operators can plausibly leave a secondary/staging org unset while other orgs are fully configured, at which point the attack requires nothing more than a single unauthenticated POST to `/webhooks`.

### Recommendation
Cross-validate: after resolving the target repository/stack via `repository.full_name`, verify that the resolved repository's owning organization is the same organization whose key satisfied `verify_signature` (i.e., re-derive the expected organization from the resolved `Repository`/`Stack` record, not solely from the unauthenticated `repository.owner.login` field used to pick the HMAC key). Additionally, do not allow `verify_webhook_signature` to silently return `true` for organizations with a blank `webhook_secret`; require an explicit opt-in (e.g., an `unsigned_webhooks_allowed: true` flag) rather than treating "no secret configured" as "accept unsigned".

### Proof of Concept
Given a multi-org config (per `docs/setup.md`):
```yaml
github:
  OrgA:
    webhook_secret: supersecretA
    ...
  OrgB:
    webhook_secret: # nil - no secret configured
    ...
```
Both `OrgA/real-repo` and `OrgB/anything` have Shipit stacks. An attacker sends, with no `X-Hub-Signature` matching anything real:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=deadbeef
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgB" },
    "full_name": "OrgA/real-repo"
  }
}
```
`verify_signature` resolves `Shipit.github(organization: "OrgB")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally per `lib/shipit/github_app.rb` line 77, letting the request through with status 200. `PushHandler#stacks` then resolves `Repository.from_github_repo_name("OrgA/real-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for every matching, non-archived stack — acting on `OrgA`'s repository despite the request only being "authenticated" (trivially) against `OrgB`.

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
