### Title
Cross-organization webhook authentication bypass via mismatched `owner`/`full_name` binding in signature verification - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a webhook against using `repository.owner.login` (or `organization.login`) taken from the **unverified** JSON body, while every event handler that actually mutates data selects the target `Stack`/`Repository` using `repository.full_name` — a *different* field from the same untrusted body. Nothing enforces that these two fields refer to the same organization, and if any configured organization has no `webhook_secret` set (an explicitly supported, documented configuration), signature verification for that organization always passes regardless of the signature header. This lets an attacker choose an org with no secret to pass verification while pointing `repository.full_name` at a stack belonging to a completely different, "protected" organization.

### Finding Description
`verify_signature` picks the app/secret to validate against from attacker-supplied data, then validates: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` when no `webhook_secret` is configured for that organization: [3](#0-2) 

Meanwhile, every webhook handler (base class shared by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves the actual target `Stack`/`Repository` from a *different* JSON field, `repository.full_name`: [4](#0-3) [5](#0-4) 

Because `repository.owner.login` (used to pick the signing secret) and `repository.full_name` (used to pick the acted-upon repository) both come from the same attacker-controlled JSON body, and the code never checks that they are consistent, the binding that should hold is:

`organization whose secret validated the request == organization owning the repository being acted upon`

This equality is never enforced. If the Shipit instance is configured for multiple GitHub organizations (a documented supported mode) and at least one of them has no `webhook_secret` set (also documented as optional, `webhook_secret: # nil`), an attacker can:
1. Set `X-Github-Event` to `push`/`status`/`check_suite`.
2. Set `repository.owner.login` (or top-level `organization.login`) to the unsecured org's name, so `verify_signature` resolves that org's `GitHubApp` and `verify_webhook_signature` returns `true` unconditionally, no matter what `X-Hub-Signature` header is sent.
3. Set `repository.full_name` to `"<protected-org>/<victim-repo>"`, so the handler resolves and mutates the victim `Stack` belonging to the protected, secret-bearing organization.

### Impact Explanation
This breaks the authentication boundary between organizations entirely: an unauthenticated network attacker who knows only the name of an unsecured org configured on the instance can forge webhook events that mutate state for stacks belonging to a *different*, secured organization. Concretely, forging a `status` event lets an attacker create arbitrary `Status` records (state, description, target_url) on commits of a victim stack, which can be used to fake passing CI/required checks that gate deploys, and forging `push` events can trigger unwanted `sync_github` cycles on victim stacks. This crosses the "unauthorized deploy" / cross-repository-writes impact bar without requiring any credential, token, or session.

### Likelihood Explanation
Likelihood depends on operator configuration: this is only exploitable when the Shipit instance is configured with multiple GitHub organizations and at least one of them has `webhook_secret` left unset — both of which are explicitly supported and documented as valid configurations (webhook secret is described as "optional"). In that state, exploitation requires no secret, token, or account at all, only knowledge of the unsecured org's name and the target repo's `full_name`, both of which are typically public.

### Recommendation
Bind verification to the same field used for routing: verify the signature using the organization/app resolved from `repository.full_name` (not `repository.owner.login`/`organization.login`), or explicitly assert that `repository.owner.login` equals the owner segment of `repository.full_name` before dispatching to handlers. Additionally, consider requiring `webhook_secret` to be present for every configured organization (reject boot/configuration if any org lacks one) so `verify_webhook_signature` can never silently return `true`.

### Proof of Concept
Given a Shipit instance configured with two orgs, `no-secret-org` (no `webhook_secret`) and `victim-org` (has `webhook_secret`), with a stack tracking `victim-org/victim-repo`:

```
POST /webhooks HTTP/1.1
X-Github-Event: status
X-Hub-Signature: sha1=0000000000000000000000000000000000000000

{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "description": "forged",
  "context": "ci/required-check",
  "target_url": "https://attacker.example",
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```

`verify_signature` resolves `Shipit.github(organization: 'no-secret-org')`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally regardless of the bogus `X-Hub-Signature`. `StatusHandler` (via `Handler#repository_name`) then resolves `victim-org/victim-repo` and creates a forged success `Status` on the victim commit.

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
