### Title
Webhook signature is verified against the organization named in `repository.owner.login`, while the repository actually mutated is selected from the unrelated `repository.full_name` field — allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`), but every downstream `Webhooks::Handlers::Handler` resolves the repository/stack to act on using the completely independent `repository.full_name` field of the same JSON body. If any configured GitHub organization has no `webhook_secret` set, signature verification for that organization is a no-op, and an attacker can submit a forged, unsigned webhook that claims to be from that unsecured organization while pointing `repository.full_name` at a *different*, fully-tracked stack.

### Finding Description
`verify_signature` picks the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

The actual HMAC check is keyed to that organization's `GithubApp` instance, and — critically — is a no-op when no secret is configured for that organization: [3](#0-2) 

Meanwhile, every webhook handler resolves the target `Repository`/`Stack` from a *different* field of the very same payload — `repository.full_name` — with no cross-check against the `repository.owner.login`/`organization.login` used for signature selection: [4](#0-3) [5](#0-4) 

The binding that should hold is: **organization authenticated (via `repository_owner` → signature check) == organization whose repository is written (via `repository.full_name` → `stacks`)**. Because these two values are read from independently-attacker-controlled parts of an unauthenticated JSON body, and because the "authenticated" side can trivially be satisfied by naming any organization configured without a `webhook_secret`, the two sides diverge.

### Impact Explanation
An unprivileged internet user (this endpoint has no authentication and CSRF protection is explicitly skipped) can:
1. Configure the forged payload's `repository.owner.login` (or `organization.login`) to a GitHub organization known to be onboarded to this Shipit instance without a `webhook_secret` set — for that organization, `verify_webhook_signature` unconditionally returns `true`.
2. Set `repository.full_name` to `victim-org/victim-repo`, an entirely different, properly-secured organization's repository that has active Shipit stacks.
3. Any handler for that event type (`status`, `push`, `check_suite`, `pull_request`, `membership`, etc.) then operates on `victim-org/victim-repo`'s real stacks/commits using attacker-supplied data, e.g. forging a commit `Status` (`success`), which feeds directly into `Commit#deployable?`'s CI gate: [6](#0-5) 

Forging a "success" CI status on an otherwise-blocked commit removes the CI gate that `deployable?` enforces, enabling an unauthorized deploy of a commit that never actually passed CI on the victim repository — matching the Critical/High "unauthorized deploy" impact bucket, achieved purely by exploiting the authentication-organization vs. write-repository mismatch, without any credential, token, or repository write access.

### Likelihood Explanation
Likelihood is moderate-to-high in realistic operator configurations: `webhook_secret` is explicitly optional per organization (`@config[:webhook_secret].presence`), and multi-tenant Shipit deployments commonly onboard several GitHub organizations, some early/low-risk ones without secrets configured yet. Any single such organization existing in the configuration is enough to unlock forged writes against every other organization's repositories tracked by the same Shipit instance, since the field used for the write-target lookup is never tied back to the field used for authentication.

### Recommendation
Bind the authenticated organization to the acted-upon repository: after signature verification succeeds, require that `repository.full_name`'s owner segment matches the `repository_owner`/`organization.login` used to select the signing secret, and reject the request otherwise. Alternatively, always resolve the signing key from the same field (`repository.full_name`'s owner) that handlers use for repository lookup, and forbid organizations with a blank `webhook_secret` from validating signed traffic for any repository they don't literally own.

### Proof of Concept
1. Ensure the Shipit instance has at least two configured GitHub orgs: `unsecured-org` (no `webhook_secret`) and `victim-org` (properly secured, with an actively tracked stack for `victim-org/victim-repo`).
2. As an anonymous client, POST to `/webhooks` with:
   - `X-Github-Event: status`
   - No/garbage `X-Hub-Signature` header.
   - Body:
     ```json
     {
       "repository": { "owner": { "login": "unsecured-org" }, "full_name": "victim-org/victim-repo" },
       "sha": "<existing commit sha in victim-org/victim-repo>",
       "state": "success",
       "context": "ci/forged",
       "branches": [{ "name": "master" }]
     }
     ```
3. `verify_signature` resolves `Shipit.github(organization: "unsecured-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/invalid) signature header.
4. The `status` handler processes the payload and creates a `Status` record for the commit in `victim-org/victim-repo`, using `repository.full_name` — an org the attacker never authenticated against — potentially flipping `Commit#deployable?` to `true` for a commit that should remain blocked.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
