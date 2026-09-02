### Title
Webhook signature verification binds to `repository.owner.login`, but every handler acts on the unverified `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC against using `repository.owner.login` (or `organization.login`) taken directly from the untrusted JSON body, before the signature is checked. Every webhook `Handler` (push, pull_request/*) instead locates the `Stack`/`Repository` to act on using a completely different field, `repository.full_name`, which is never compared against the organization used for signature selection.

### Finding Description
The verification step is: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`repository_owner` selects the `GitHubApp` config (and therefore the `webhook_secret`) via `Shipit.github(organization: repository_owner)`, and `verify_webhook_signature` HMAC-checks the raw body against that org's secret: [3](#0-2) 

Once the signature is accepted, `Handler#stacks`/`#repository` resolve the target repository from an entirely different, unchecked field: [4](#0-3) 

```
def repository_name
  payload.dig('repository', 'full_name')
end
```

All processing handlers (`PushHandler`, `PullRequest::ClosedHandler`, `PullRequest::LabeledHandler`, etc.) reuse this same pattern — they take `params.repository.full_name` to find the `Repository`/`Stack` to mutate: [5](#0-4) [6](#0-5) [7](#0-6) 

Shipit explicitly supports multiple, independently configured GitHub Apps/organizations sharing one engine instance, each with its own `webhook_secret`: [8](#0-7) 

The binding that should hold is: **organization authenticated (via `repository.owner.login` → selected `webhook_secret`) == repository that is written (via `repository.full_name` → `Repository.from_github_repo_name`)**. Because the signature check only covers the choice of *which secret* is used, and HMAC covers the raw body as a whole, an attacker who legitimately controls one tenant organization (e.g., "OrgTwo", with a real, valid `webhook_secret` they know because they administer that GitHub App/organization) can forge a payload where `repository.owner.login = "OrgTwo"` (to select their own secret and pass HMAC verification) while `repository.full_name = "OrgOne/some-private-repo"` (a different tenant's tracked repository). The signature will validate correctly (it is computed over the exact bytes sent, with the secret the attacker knows), yet the handler acts on "OrgOne/some-private-repo" — a repository the attacker does not control and for which they have no valid GitHub-issued webhook.

### Impact Explanation
This breaks the deployment-trust binding between "organization whose credentials were verified" and "repository whose state is mutated," letting an attacker who is an unprivileged, single-tenant GitHub App owner (i.e., unprivileged with respect to any other org tracked by the same Shipit instance) trigger writes against another organization's Stack:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` → enqueues `GithubSyncJob`, which fetches commits via the *victim* stack's own `github_api` (using Shipit's app credentials for that org) and appends attacker-chosen `expected_head_sha` hints, potentially forcing sync/retry cycles or feeding spoofed head SHAs into deploy-eligibility logic.
- `PullRequest::ClosedHandler`/`LabeledHandler` can archive/unarchive review stacks belonging to a foreign repository based purely on attacker-forged PR metadata.

This is a cross-repository / cross-tenant write triggered without possessing that tenant's real webhook secret, satisfying the "cross-repository writes" criterion for Critical severity, though the concrete blast radius (whether it can force an actual unauthorized deploy/merge) depends on downstream stack state and is not fully traced here.

### Likelihood Explanation
Exploitability requires the attacker to control at least one legitimate, distinct GitHub organization/App configured in the same multi-tenant Shipit deployment (as the engine's own test fixtures demonstrate is a supported configuration) — i.e., they must be a valid tenant admin of *some* org, but not of the target org whose repository they forge writes against. Given that Shipit is designed to host multiple organizations behind one instance with per-org secrets, and the field mismatch is unconditional in every handler, this is straightforward to trigger with a single crafted webhook POST.

### Recommendation
In `Handler#repository_name` (and in `WebhooksController#repository_owner`), require that `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` used to select and verify the webhook secret, rejecting payloads where the two disagree, before any handler processes the event.

### Proof of Concept
1. Attacker administers "OrgTwo" as a real Shipit-configured GitHub App with `webhook_secret = S2`.
2. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "OrgOne/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S2, raw_body)` themselves (they know `S2`).
4. `WebhooksController#verify_signature` resolves `repository_owner => "OrgTwo"`, fetches `Shipit.github(organization: "OrgTwo")`, and the HMAC check passes.
5. `PushHandler#stacks` resolves via `Repository.from_github_repo_name("OrgOne/victim-repo")`, enqueuing `GithubSyncJob` for a stack under an organization the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
```
