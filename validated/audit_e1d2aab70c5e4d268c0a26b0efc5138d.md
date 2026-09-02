### Title
Webhook signature verified against `repository.owner.login`/`organization.login` but stack mutation keyed on `repository.full_name` — organization-authentication/repository-written binding break ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization webhook secret to check the HMAC signature against using `repository_owner` (`repository.owner.login`, falling back to `organization.login`). The event dispatch, however, resolves the *target* repository/stack to mutate via `Handler#repository_name`, which reads a **different** field of the same attacker-supplied JSON body: `repository.full_name`. These two fields are never cross-checked against each other, so the "organization that authenticated" and the "repository that is written" are not the same binding.

### Finding Description
`verify_signature` picks the verifying secret solely from `repository_owner`: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` returns `true` unconditionally whenever the resolved organization has no `webhook_secret` configured: [3](#0-2) 

This is not a theoretical edge case — it is the shipped default state in this engine's own configuration templates (`webhook_secret: null` / commented-out `webhook_secret:`): [4](#0-3) [5](#0-4) 

Meanwhile, once `verify_signature` passes (whether legitimately or because that organization has no secret configured), `create` dispatches the parsed JSON straight to the handlers: [6](#0-5) 

Every handler resolves the affected stack(s) not from `repository_owner`/`organization.login` (the field the signature check keyed on) but from `repository.full_name`: [7](#0-6) [8](#0-7) 

Concretely: `push` triggers a resync of any stack whose repository's `full_name` matches the attacker-chosen value: [9](#0-8) 

This is the exact shape of the reported Oracle bug: two mapping/verification entries are populated together from one context (`_setAssetsSources` keys by `asset`, or here — the signature check keys by `repository_owner`) but a *different* key from the same request is used at the point where the value is actually acted upon (`_assetToTimeout[asset]` vs. `[underlying]`, or here — `repository_owner` for auth vs. `repository.full_name` for the mutated resource).

### Impact Explanation
An attacker who knows (or guesses) the name of **any** GitHub organization configured in this Shipit instance that has no `webhook_secret` set (common for initial/simple/single-tenant setups, as shown in the engine's own default templates) can:
1. POST directly to `/github/webhooks` with `repository.owner.login` (or `organization.login`) set to that unsecured organization — signature check passes unconditionally, regardless of the `X-Hub-Signature` value sent.
2. Set `repository.full_name` in the same payload to `"other-org/other-repo"` — any other tracked repository in the instance, including ones belonging to organizations that *do* have a real `webhook_secret` the attacker does not know.
3. The dispatched handler (`push`, `status`, `check_suite`, `pull_request`, `membership`) acts on the stack(s)/repository resolved from `full_name`, completely bypassing the fact that no valid signature exists for that organization/repository.

Depending on event type this allows forging `status`/`check_suite` events (fabricating green CI on an arbitrary tracked repository's commit, which — combined with `continuous_deployment: true` stacks gated only on CI status — can trigger an unauthorized automatic deploy), forging `push` events to force resyncs, or forging `membership`/`pull_request` events against repositories/organizations the attacker does not control. This crosses the "organization that authenticated versus the repository that is written" binding explicitly called out as in-scope, and its worst-case outcome (an unauthorized deploy triggered by forged CI status on a `continuous_deployment` stack) meets the Critical impact bar.

### Likelihood Explanation
No credential, GitHub write access, or `webhook_secret` knowledge is required by the attacker — the exploit specifically relies on an organization for which no secret is configured (an intentionally supported, documented configuration state), which is exactly the class of unprivileged-attacker scenario the rules ask to prioritize (only the *absence* of a secret is leveraged, not possession of one). Any multi-organization or "not-yet-hardened" Shipit deployment (as reflected by the engine's own shipped default secrets templates) is susceptible.

### Recommendation
Bind the verified signature/organization to the same repository field used by handlers. Concretely: after resolving `repository_owner`, verify that `payload.dig('repository', 'full_name')` actually belongs to that owner (e.g., `full_name.split('/').first.casecmp?(repository_owner)`) before dispatching to handlers, or better, derive `repository_owner` from `full_name` itself so a single, signature-checked field drives both the org lookup and the acted-upon repository.

### Proof of Concept
```
POST /github/webhooks HTTP/1.1
X-Github-Event: status
X-Hub-Signature: sha1=anything     # ignored: org "unsecured-org" has no webhook_secret configured

{
  "sha": "<victim commit sha on tracked stack>",
  "state": "success",
  "context": "ci/required",
  "target_url": "https://attacker.example/fake",
  "branches": [{"name": "master"}],
  "repository": {
    "owner": {"login": "unsecured-org"},
    "full_name": "victim-org/victim-repo"
  }
}
```
`verify_signature` resolves `Shipit.github(organization: "unsecured-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the bogus `X-Hub-Signature`. The `status` handler then records a fabricated successful `CommitStatus` against `victim-org/victim-repo`'s commit, which for a `continuous_deployment: true` stack can trigger an unauthorized deploy.

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

**File:** test/dummy/config/secrets.test.json (L7-12)
```json
  "github": {
    "domain": null,
    "app_id": 42,
    "installation_id": 43,
    "bot_login": "shipit[bot]",
    "webhook_secret": null,
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
