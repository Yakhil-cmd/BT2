### Title
Webhook signature verified against the payload's `repository.owner.login` while the event is applied to a repository resolved from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to validate the HMAC against using `repository_owner`, taken from the same untrusted, not-yet-verified payload. Every downstream handler, however, resolves which `Repository`/`Stack` to act on using a *different* payload field, `repository.full_name`. Because Shipit supports multiple organizations each with its own `GitHubApp` config/`webhook_secret` (`Shipit.github(organization: ...)`), a payload can be crafted so the "authenticating organization" and the "repository being written to" diverge, exactly mirroring the C4 finding's "check field A, but the code that matters trusts field B" bug class.

### Finding Description
`verify_signature` derives the signing organization purely from the JSON body, before any authenticity check has occurred: [1](#0-0) [2](#0-1) 

The organization derived here (`repository.owner.login`, falling back to `organization.login`) selects the `GitHubApp` instance and thus the `webhook_secret` used for `verify_webhook_signature`: [3](#0-2) 

Once the request passes this check, the actual `push`/`check_suite` handlers never look at `repository.owner.login` again. They resolve the target `Repository` from `repository.full_name`: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` then does an owner+name lookup keyed to whatever `full_name` says: [6](#0-5) 

and each `Repository` is itself scoped to its own `GitHubApp` by `owner`: [7](#0-6) 

The binding that should hold is:
`organization used to select the webhook_secret for signature verification == organization that owns the repository the handler mutates`

Nothing enforces `repository.owner.login == repository.full_name.split('/').first`. An attacker who is a legitimate maintainer/admin of one organization "OrgA" registered with this Shipit instance (and therefore able to produce a validly-signed webhook body for OrgA, using OrgA's own webhook secret which they control, e.g. by editing OrgA's webhook settings) can submit a `push` payload where:
- `repository.owner.login = "OrgA"` (so `verify_signature` validates against OrgA's secret, which the attacker legitimately possesses/controls)
- `repository.full_name = "OrgB/some-repo"` (a stack belonging to a completely different, unrelated organization hosted by the same Shipit instance)

`verify_signature` succeeds (OrgA's secret matches), but `PushHandler` calls `stack.sync_github` against `OrgB/some-repo`'s stacks, which are stacks the attacker was never authorized to affect. This is the "organization authenticated vs. repository written" binding break called out in scope.

### Impact Explanation
Successful exploitation lets an attacker who only controls their own organization's webhook secret trigger `stack.sync_github` (and other push/check_suite side effects) on stacks belonging to a repository in a different organization served by the same Shipit deployment — i.e., a cross-organization/cross-repository write of Shipit's internal state driven by a forged (from OrgB's perspective) webhook. Depending on what `sync_github` and related callbacks do (queueing GithubSyncJob, refreshing commits/check runs which feed into deploy eligibility), this can influence deploy/CD decisions for a repository the attacker does not own, which matches the "cross-repository writes" / "unauthorized deploy or rollback" impact class.

### Likelihood Explanation
This requires the attacker to be a legitimate, GitHub-webhook-configuring member of at least one organization already registered with the Shipit instance (multi-tenant deployments only) — no Shipit `ApiClient` token, `github_access_token`, or Shipit session is needed. Given that Shipit is explicitly designed to be configured with multiple GitHub organizations (`Shipit.github(organization:)`), this is a realistic operating mode, making the likelihood moderate wherever multi-org hosting is in use.

### Recommendation
Bind signature verification and repository resolution to the same trusted field. Concretely, after verifying the signature for `repository_owner`, re-check that every handler's resolved `repository.full_name` owner matches `repository_owner` (or, simpler, have handlers accept the already-verified organization and reject/ignore events whose `repository.full_name` owner disagrees with it) before performing any stack lookups or mutations.

### Proof of Concept
1. Attacker is an admin of `OrgA`, a Shipit-registered GitHub organization, and knows `OrgA`'s webhook secret (e.g., they configured it themselves in GitHub's org webhook settings, or extracted it from their own installation config).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POSTs to `/webhooks`.
4. `WebhooksController#verify_signature` computes `repository_owner = "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the HMAC matches — request is accepted (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`).
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgB/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56`) and calls `stack.sync_github(...)` on `OrgB`'s stacks — actions the attacker never had signing authority over.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```
