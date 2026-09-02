### Title
Webhook organization used for signature verification is decoupled from the repository actually acted upon, allowing forged CI/push events against protected stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/HMAC secret to validate a webhook against using `repository_owner`, a value read out of the attacker-supplied JSON body itself. All downstream `Shipit::Webhooks::Handlers::Handler` subclasses (push, status, check_suite, etc.) instead resolve the `Stack`/`Repository` they operate on from a *different* field of the same body: `repository.full_name`. Because GitHub App webhook secrets are documented and configured as optional per organization, and `verify_webhook_signature` becomes a no-op when a secret is blank, an attacker who knows (or guesses) the login of any organization configured in this Shipit instance without a `webhook_secret` can produce a payload that (a) passes signature "verification" trivially for that unprotected org, while (b) naming a completely different, protected organization's repository in `repository.full_name` for the handler to act on. The org that "authenticates" the request and the repository whose Stack is actually written to are never checked for consistency.

### Finding Description
`verify_signature` derives the signing organization purely from JSON fields in the untrusted body: [1](#0-0) [2](#0-1) 

The actual HMAC check is a documented no-op when the target org has no configured `webhook_secret` (an explicitly *optional* field per `docs/setup.md` — "Webhook secret (optional)"): [3](#0-2) 

Meanwhile, every webhook `Handler` (push, status, check_suite, membership follow different code but share this base for repo-scoped events) resolves the target `Repository`/`Stack` from a *different* field, `repository.full_name`, with no cross-check against the org used above for verification: [4](#0-3) 

`PushHandler`, for example, uses this shared `stacks` resolution to trigger a GitHub sync directly from attacker-controlled `full_name`: [5](#0-4) 

This is exactly the accounting-mismatch bug class from the reference report, generalized to a trust binding: `repository_owner` (the org whose secret authenticates the request) ≠ `repository.full_name`'s owner (the repository actually written). Nothing in `WebhooksController` or `Handler` enforces:
```
repository_owner == repository.full_name.split('/').first
```
Multi-org deployments are an explicitly supported, first-class configuration (see `test/dummy/config/secrets_double_github_app.yml`, which configures two orgs, `OrgOne` and `OrgTwo`, each with `webhook_secret: # nil`), so having at least one org without a secret configured while other orgs/stacks are meant to be protected is a realistic deployment shape, not a contrived edge case.

### Impact Explanation
Any handler that writes state used to gate deploys/merges is affected, since none of them re-validate that the org used for the (potentially no-op) signature check matches the repository actually being mutated. Concretely, an attacker who can reach the public `/webhooks` endpoint and knows the login of one org configured without a `webhook_secret` can:
- Send a `push` event with `repository.owner.login` = the unprotected org (bypasses/no-ops signature check) and `repository.full_name` = `<protected-org>/<protected-repo>`, forcing `Stack#sync_github` to run against a stack the attacker has no GitHub privileges over.
- Send `status`/`check_suite` events the same way, injecting fabricated CI/check results into Shipit's own database for a protected stack's commits (via the same `Handler#stacks` → `full_name` resolution). Since Shipit's continuous-delivery and merge-queue gating consult these locally-stored CI statuses/check runs, this can unblock an "unauthorized deploy" or "unauthorized merge" — one of the explicitly listed Critical impacts.

This crosses the credential/authentication boundary described in the rules: "an organization that authenticated versus the repository that is written."

### Likelihood Explanation
Likelihood depends on operator configuration (at least one org without `webhook_secret`), but this is not a hardening recommendation being ignored — it's a state the engine explicitly documents and ships test fixtures for as normal (`webhook_secret` is optional, and the double-org fixture in `test/dummy/config/secrets_double_github_app.yml` sets it to nil for both configured orgs). No GitHub App private key, session, or `ApiClient` token is required — only network access to the public `/webhooks` endpoint and knowledge of one configured org's login string, which is often publicly discoverable (it's the org name in Shipit's own URLs/stack names).

### Recommendation
In `Handler#repository_name` (and any other webhook-payload field used to select which `Stack`/`Repository` to mutate), require that the resolved repository's owner match the same `repository_owner`/organization that `WebhooksController#verify_signature` used to select the signing secret, and reject the request otherwise. Additionally, consider making `webhook_secret` mandatory (or at least warn loudly / fail closed) for any organization that has repositories mapped to Shipit stacks, rather than silently treating a blank secret as "always verified."

### Proof of Concept
Preconditions: Shipit instance configured with two orgs in `secrets.yml`, e.g. `unprotected-org` (no `webhook_secret`) and `protected-org` (has `webhook_secret` and a Stack for `protected-org/app`).

```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything-or-absent

{
  "sha": "<protected-org/app commit sha>",
  "state": "success",
  "context": "ci/tests",
  "branches": [{"name": "master"}],
  "repository": {
    "full_name": "protected-org/app",
    "owner": {"login": "unprotected-org"}
  }
}
```
- `verify_signature` computes `repository_owner` = `"unprotected-org"` [2](#0-1) , loads that org's `GithubApp`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally [6](#0-5) .
- The status handler (via `Handler#repository_name`/`#stacks`) resolves the target using `repository.full_name` = `"protected-org/app"` [4](#0-3) , and writes a forged `success` status against `protected-org`'s stack despite the request never being authenticated by `protected-org`'s own webhook secret.

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
