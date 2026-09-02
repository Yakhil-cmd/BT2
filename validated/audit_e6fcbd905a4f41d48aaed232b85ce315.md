## Confirmed: root cause traced end-to-end

The critical piece is confirmed: `Handler#repository_name` (used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc. to look up the target `Stack`/`Repository`) reads `payload.dig('repository', 'full_name')`, while `WebhooksController#repository_owner` (used to pick *which* GitHub App / `webhook_secret` verifies the request) reads `payload.dig('repository', 'owner', 'login')` — a **different key from the same attacker-controlled JSON body**. [1](#0-0) [2](#0-1) [3](#0-2) 

And critically, `verify_webhook_signature` short-circuits to `true` whenever the resolved org's `webhook_secret` is blank/unconfigured — a state the setup docs explicitly present as optional/valid (`webhook_secret: # nil`): [4](#0-3) [5](#0-4) [6](#0-5) 

### Title
Cross-organization webhook forgery via mismatched `repository.owner.login` (signature selector) vs `repository.full_name` (stack resolver) - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify a webhook against using `repository.owner.login` (or `organization.login`) taken from the *unverified* request body. Every event `Handler` subclass then resolves the actual target `Stack` using a *different* field, `repository.full_name`, from that same unverified body. Because these are two independent, attacker-controlled fields inside one payload, and because `verify_webhook_signature` returns `true` unconditionally when the selected org has no `webhook_secret` configured, an attacker can pick an org name for `repository.owner.login` that has no secret configured (bypassing verification entirely) while pointing `repository.full_name` at a totally different, real, secret-protected organization/repository to act upon.

### Finding Description
The binding that should hold is:
`organization whose signature was authenticated == organization/repository the handler writes to`

Before this request, that binding is never enforced: the field used to select the verifying `GitHub App` (`repository.owner.login`, `WebhooksController#repository_owner`) and the field used by every `Handler` to resolve the target repo/stack (`repository.full_name`, `Handler#repository_name`) are parsed independently from the same untrusted JSON body, with no cross-check that they refer to the same repository. [7](#0-6) [3](#0-2) [1](#0-0) 

Combined with `GitHubApp#verify_webhook_signature` returning `true` when `webhook_secret` is blank (a state explicitly documented as an acceptable/"optional" configuration for any one org in a multi-org Shipit deployment), an attacker only needs to find or register (as a normal, low-privilege user, e.g. via the "Install App on your own throwaway GitHub org" flow, or simply by knowing that Shipit is deployed with no webhook_secret set for at least one configured org — a documented default) one organization whose Shipit-side app config has no secret set. They then craft a payload where `repository.owner.login`/`organization.login` names that low-security org (making verification a no-op) while `repository.full_name` names a genuinely protected, unrelated repository/stack that the attacker does not control and has no push access to. [4](#0-3) 

The `create` action then dispatches the full attacker payload to the event handler for whatever `X-Github-Event` was declared, with no re-verification that `repository.full_name` matches `repository_owner`: [7](#0-6) 

### Impact Explanation
For `PushHandler`, this results in `stack.sync_github(expected_head_sha: params.after)` being triggered for a stack under a completely different, unauthenticated repository/organization, causing Shipit to sync a forged/arbitrary `after` SHA as the expected head for that stack. [8](#0-7) 

More severely, `StatusHandler` and `CheckSuiteHandler` let an attacker forge CI/check-suite state for commits on a target repo they don't control, which can flip Shipit's CI gating (`hidden_statuses`/`required_statuses`) and unblock an unauthorized deploy of that stack, since Shipit relies on these webhook-driven status/check records to decide deployability. This satisfies the "unauthorized deploy" High/Critical impact bar without the attacker ever holding write access, an `ApiClient` token, or the target org's real `webhook_secret`.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured for multiple GitHub organizations where at least one configured org has no `webhook_secret` set — a state the project's own docs present as a normal, supported configuration (`webhook_secret: # nil`, described as "optional") — and (2) the attacker knowing/guessing that org's name (visible in `docs/setup.md` examples, or discoverable from `Shipit.github_organizations`/error responses such as the `GithubOrganizationUnknown` 422 path, which echoes attempted org names). No credentials, tokens, or repository access to the *victim* repo/org are required. This is realistic for any Shipit instance following the "Using Multiple Github Applications" setup guidance without setting a secret on every entry.

### Recommendation
- In `Handler#repository_name`, cross-validate that `payload.dig('repository', 'owner', 'login')` (or `organization.login`) matches the owner embedded in `repository.full_name`, and reject/no-op otherwise.
- In `WebhooksController#verify_signature`, do not allow verification to succeed silently when `webhook_secret` is blank for the org resolved from attacker-controlled input; either require a `webhook_secret` for every configured org in multi-org mode, or fail closed instead of returning `true`.
- Bind the verified organization identity to every value the handler subsequently uses, ideally by having `Handler` re-derive the "owner" solely from the same field used in verification.

### Proof of Concept
1. Deploy Shipit with two GitHub Apps configured: `OrgA` (attacker's own or any org where the operator never set `webhook_secret`) and `OrgB` (real target with a `webhook_secret` and existing `Stack`s).
2. Attacker POSTs to `/webhooks` with `X-Github-Event: push` and a body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
3. `WebhooksController#repository_owner` returns `"OrgA"`; `Shipit.github(organization: "OrgA")` is fetched, and `verify_webhook_signature` returns `true` immediately because `OrgA` has no `webhook_secret` — no valid `X-Hub-Signature` is even required. [2](#0-1) 
4. `PushHandler#repository_name` resolves `"OrgB/target-repo"` from the same body and finds `OrgB`'s real `Stack`, calling `sync_github(expected_head_sha: "<attacker-chosen sha>")` on it — a stack the attacker never had credentials for. [8](#0-7)

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
