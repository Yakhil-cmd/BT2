### Title
Webhook signature verification selects the trust anchor from attacker-controlled payload data, allowing cross-organization signature bypass - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification based on a field (`repository.owner.login` / `organization.login`) taken directly from the unverified request body, before the signature has been checked. Because Shipit supports multiple configured GitHub organizations/apps (each with its own, independently-optional `webhook_secret`), an attacker can pick an organization whose app config has no `webhook_secret` set, and Shipit's verifier will unconditionally accept the request — while the payload's `repository.full_name` (used afterward to select the actual `Stack`/`Repository` that gets acted upon) can point to a completely different, properly-secured organization.

### Finding Description
`verify_signature` selects the verification secret using attacker-supplied data: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`repository_owner` is computed from `params`, i.e. `JSON.parse(request.raw_post)` — fully attacker-controlled and read before any cryptographic check occurs. This value is used to look up the `Shipit::GithubApp` instance whose secret will validate the signature:

```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```

Critically, `Shipit::GithubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatic success: [3](#0-2) 

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Shipit's multi-organization configuration is an officially supported pattern — the test fixtures show a two-organization setup where one organization (`OrgTwo`) has no `webhook_secret` configured at all: [4](#0-3) 

After the (bypassable) signature check "passes", the actual event is dispatched to handlers using a *different* field from the same untrusted payload — `repository.full_name` — to resolve the repository/stack to act on: [5](#0-4) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

So the binding that should hold is:
`organization whose secret validated the signature == organization owning the repository the handler acts on`

but nothing enforces this. An attacker can set `repository.owner.login` (or `organization.login`) to an org with no secret configured (verification trivially returns `true`), while setting `repository.full_name` to `"<victim-org>/<victim-repo>"`, a completely different, properly-secured organization/repository tracked by the same Shipit instance. The webhook is processed as if it legitimately originated from GitHub for the victim's repository, without ever knowing the victim organization's real `webhook_secret` or its private key.

This is directly analogous to the `_deployedAmount` bug: state (`_deployedAmount`) used for one purpose (fee accounting) diverges from the state actually mutated by `undeploy` (the real balance) — here, the *identity used to validate trust* (`repository_owner`) diverges from the *identity actually written to* (`repository.full_name`), and both are drawn from the same untrusted input with no cross-check.

### Impact Explanation
Any of the webhook event handlers can be triggered against a targeted, security-conscious org/repo by "signing" the payload under a laxly-configured (or attacker-known-secret) sibling organization on the same Shipit instance. Concretely:
- A forged `status` event (see `test/controllers/webhooks_controller_test.rb:42-59`) can create arbitrary passing CI `Status` entries on a victim commit, which can satisfy `required_statuses`/`blocking_statuses` gating in `deploy_spec.rb` and enable `continuous_deployment` to auto-trigger an unauthorized deploy of an existing commit.
- A forged `push` event enqueues `GithubSyncJob` for a victim stack.
- A forged `check_suite` event enqueues `RefreshCheckRunsJob`, similarly affecting deploy gating.
- `membership`/`pull_request` handlers can mutate teams/PR metadata cross-organization.

This crosses the "unauthorized deploy" / "cross-repository writes" impact bar defined in the engine's threat model, entirely from an unauthenticated network position (no `ApiClient` token, no session, no GitHub credentials needed) as long as any organization configured on the instance lacks a `webhook_secret` (a supported and, per the fixtures, real configuration state) — or the attacker otherwise knows any one organization's secret.

### Likelihood Explanation
Requires only that the Shipit deployment host multiple GitHub organizations (a documented/supported feature) where at least one has no `webhook_secret` set, or that the attacker has learned any single org's webhook secret (e.g. as a legitimate contributor to that unrelated org). No privileged Shipit credentials, sessions, or GitHub App keys are required. This is a config-shape issue baked into the verification logic itself rather than a one-off misconfiguration of the target org.

### Recommendation
Do not select the signing/verification org from unverified payload fields that are also used later to route/act on data. Either:
- Verify against every configured organization's secret and require the payload's `repository.full_name` organization to match the org whose secret validated the signature, rejecting on mismatch; or
- Bind webhook delivery routes to a specific organization (e.g. via a per-org URL path or app installation ID resolved independently of the JSON body) so the secret used for verification cannot be chosen by the request body; and
- Do not allow a configured organization to have `verify_webhook_signature` unconditionally return `true` when `webhook_secret` is blank — require an explicit "no verification" opt-in per org rather than treating "unset" as "always valid," or refuse to process any event whose asserted `repository_owner` differs from the actual repository owner in `repository.full_name`.

### Proof of Concept
1. Instance is configured (per `test/dummy/config/secrets_double_github_app.yml`) with `OrgOne` (has `webhook_secret`) and `OrgTwo` (no `webhook_secret`), both hosting Shipit-tracked stacks.
2. Attacker POSTs to `/github/webhooks` with `X-Github-Event: status` and no valid `X-Hub-Signature` (or any arbitrary value), body:
```json
{
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "OrgOne/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/forged"
}
```
3. `verify_signature` computes `repository_owner == "OrgTwo"`, loads `Shipit.github(organization: "OrgTwo")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` regardless of the signature header.
4. `StatusHandler` (looked up via `Shipit::Webhooks.for_event('status')`) resolves the repository via `payload.dig('repository','full_name') == "OrgOne/victim-repo"` and creates/updates a `Status` on the victim commit in `OrgOne`, potentially unblocking a continuous deployment gate — without the attacker ever presenting `OrgOne`'s real webhook secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
