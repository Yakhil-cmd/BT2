### Title
Cross-repository forgery of commit statuses via unscoped `StatusHandler` webhook lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The GitHub webhook signature verification in `WebhooksController` binds a request only to a *GitHub organization* (via `repository.owner.login`), not to a specific *repository*. Several webhook handlers, most notably `StatusHandler`, then act on payload fields (`sha`) without any check that the addressed record actually belongs to the organization/repository that was authenticated. This breaks the binding "organization authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to verify against using only the organization name taken from the payload: [1](#0-0) [2](#0-1) 

This proves only that the sender possesses `webhook_secret` for the organization named in `repository.owner.login` (or `organization.login`). Shipit is explicitly designed to be multi-tenant across organizations, each with an independently configured `webhook_secret` (some intentionally left blank, in which case `verify_webhook_signature` short-circuits to `true`): [3](#0-2) [4](#0-3) 

Once verification passes, `Shipit::Webhooks.for_event(event)` dispatches the raw JSON `params` to handlers such as `StatusHandler`: [5](#0-4) 

`StatusHandler#process` writes a commit status purely by matching `sha` against the global `Commit` table — it never checks `repository.full_name`, and never scopes to the repository/org that was actually verified in `verify_signature`: [6](#0-5) 

Other handlers do at least scope through `repository_name`, derived from a *different* payload field (`repository.full_name`) than the one used for signature selection (`repository.owner.login`): [7](#0-6) 

Because the HMAC only proves "someone holding org X's secret sent this exact byte blob," and the same blob's `repository.owner.login`, `repository.full_name`, and `sha` fields are all attacker-controlled content within that same blob, nothing stops an attacker who legitimately controls (or is a maintainer of) one tenant organization from crafting a payload where `repository.owner.login` names their own (correctly-signed, or secret-less) organization while the `sha` targets a commit that belongs to a completely different tenant's tracked repository/stack. `StatusHandler` will happily attach an attacker-chosen `state`/`context`/`description` to that commit, regardless of which repository it truly came from.

### Impact Explanation
Commit statuses are the basis for Shipit's CI/merge gating (`ci.require`, `merge.require` in `shipit.yml`, documented in `README.md`). Forging a `success` state for a required status context on a target stack's commit can defeat CI-required checks used by the merge queue, enabling an unauthorized merge/deploy path for a repository the attacker does not control — this matches the "unauthorized deploy, rollback, or merge" Critical impact bucket, achieved purely by an actor legitimately onboarded to *any one* tenant organization of a shared Shipit instance (no repository write access, no Shipit session, no `ApiClient` token needed for a repo they don't own).

### Likelihood Explanation
Requires: (a) a multi-tenant Shipit deployment (explicitly a supported, documented configuration per `test/dummy/config/secrets_double_github_app.yml`), (b) the attacker being a legitimate holder of one tenant's `webhook_secret` (or that tenant having no secret configured, which is an explicitly supported, non-default option per `docs/setup.md`), and (c) knowledge of a target commit's SHA (public information on GitHub). All are plausible in shared/self-hosted Shipit installations serving several organizations.

### Recommendation
Bind the signature-verification organization to the same field used for repository resolution, and make every handler (especially `StatusHandler`) explicitly verify that the commit/stack being mutated belongs to the organization/repository identified by `repository.full_name`/`repository.owner.login` that was cryptographically verified — not merely match on a bare `sha`.

### Proof of Concept
1. Attacker is a legitimate admin of Org A, one tenant configured in a shared Shipit instance (`secrets.yml` → `github.OrgA.webhook_secret` present and known to them, or left blank).
2. Attacker discovers, via public GitHub, a commit SHA `S` on Org B's tracked repository/stack that has a required status context (e.g., `ci/travis`) not yet marked successful.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`, `X-Hub-Signature` computed using Org A's secret (or omitted if Org A has none), and body:
```json
{
  "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/target-repo"},
  "sha": "S",
  "state": "success",
  "context": "ci/travis"
}
```
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and passes verification using OrgA's secret.
5. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) matches `Commit.where(sha: "S")`, found on Org B's stack, and calls `create_status_from_github!`, injecting a forged "success" status onto Org B's commit — usable to satisfy Org B's merge-queue/CI gating without ever authenticating against Org B.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-8)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
```

**File:** app/models/shipit/webhooks.rb (L19-22)
```ruby
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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
