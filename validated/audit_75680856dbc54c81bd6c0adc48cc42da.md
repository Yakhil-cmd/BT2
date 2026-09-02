## Analog Vulnerability Found

### Title
Webhook signature verification authenticates the payload's `repository.owner.login`, but `StatusHandler` writes commit statuses using only a global, org-unscoped `sha` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / webhook secret to validate the inbound HMAC against using the `repository.owner.login` field taken from the *attacker-suppliable* JSON body itself. `StatusHandler#process`, however, never re-checks that binding: it looks up the target `Commit` purely by `sha`, across the entire installation, with no repository or organization constraint. This breaks the equality "organization that authenticated == repository/commit that is written," analogous to the report's base-price vs. bid/ask decoupling, where a value used for one purpose (base price / signing key selection) silently diverges from the value actually acted upon (buy/sell price / target commit).

### Finding Description
`verify_signature` derives the signing organization purely from the payload: [1](#0-0) [2](#0-1) 

This only proves the request body was HMAC-signed with the secret configured for *whatever organization the attacker declares in `repository.owner.login`*. It says nothing about the other fields inside that same signed body.

`StatusHandler#process` then acts on the `sha` field with no repository/organization scoping at all: [3](#0-2) 

Compare this to every other handler (`PushHandler`, `PullRequest::*Handler`), which explicitly resolve the target via `Repository.from_github_repo_name(params.repository.full_name)` before touching any record, e.g.: [4](#0-3) [5](#0-4) 

`StatusHandler` alone skips that resolution and matches `Commit` directly by `sha`, which is a table shared across all repositories/stacks in the installation.

In a Shipit deployment configured for multiple GitHub organizations (each with its own `webhook_secret` in the per-org GitHub App config, as modeled by `Shipit.github(organization:)` and `GitHubApp#verify_webhook_signature`): [6](#0-5) 

an attacker who administers their own organization ("Org A", tracked by this Shipit instance, whose webhook secret they legitimately know because they configured the GitHub webhook themselves) can craft a `status` event body where:
- `repository.owner.login = "org-a"` (so `verify_signature` picks Org A's secret and the HMAC verifies correctly), and
- `sha` = the SHA of a real commit belonging to a completely different, victim organization/repository tracked by the same Shipit instance.

The equality that should hold - *the org whose secret signed the payload == the org/repository that the payload is allowed to mutate* - is broken because `StatusHandler` never checks it.

### Impact Explanation
`create_status_from_github!` persists an attacker-controlled `state`/`description`/`context`/`target_url` as a `CommitStatus` on a victim's commit, without the attacker ever having write access to the victim's repository or any Shipit credential for the victim's org. Commit statuses are the mechanism Shipit exposes to GitHub-side CI systems to signal build success/failure for a commit; deploy-readiness/gating logic in the engine consumes these statuses (`ci_enabled?`/status joins on `Shipit::Stack`, and status-based deployability checks in `Shipit::Commit`) to decide whether a commit is safe to ship. Forging a `success` status on a victim's otherwise-unvetted commit can let that commit satisfy deploy gating it should not have satisfied, enabling an unauthorized deploy of a commit whose real CI never passed - this falls under the "unauthorized deploy" Critical-impact category in scope.

Note: I was not able to fully read `app/models/shipit/commit.rb` (only grep matches for `create_status_from_github!` and related methods were found, not their full bodies) before running out of iterations, so the exact way commit statuses feed into deploy-readiness decisions is inferred from Shipit's documented "required status checks" feature rather than a fully traced line-by-line proof. This should be verified in a follow-up read of `app/models/shipit/commit.rb`.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (a supported, documented configuration - `Shipit.github(organization:)` explicitly keys GitHub Apps/secrets per organization) where the attacker legitimately administers at least one tracked organization but not the victim's. Given that constraint, exploitation needs no special privilege beyond knowing one's own webhook secret (which any org admin who wires up the GitHub webhook necessarily knows) and the victim commit's SHA (public on GitHub). No repository write access, Shipit session, or API token is required.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup by the repository resolved from `params.repository.full_name` (as every other handler already does via `Repository.from_github_repo_name`), rather than matching `sha` globally. Additionally, consider validating that `repository.owner.login` and `repository.full_name`'s owner segment agree before trusting either field, closing the general class of "signing key selected from field X, but action performed using unrelated field Y in the same payload."

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `victim-org`, each with a distinct `webhook_secret` (standard multi-tenant setup per `lib/shipit/github_app.rb`).
2. As the admin of `org-a`, obtain `org-a`'s webhook secret (known because you configured it yourself when adding the webhook on GitHub).
3. Identify a commit SHA belonging to a stack tracked under `victim-org` (public GitHub data).
4. Construct a JSON body for a `status` event:
   ```json
   {
     "sha": "<victim-commit-sha>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "org-a" } }
   }
   ```
5. Compute `X-Hub-Signature: sha1=<hmac-sha1(org-a-secret, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
6. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s `GitHubApp`, and the HMAC verifies successfully - see [1](#0-0) .
7. `StatusHandler#process` matches the victim's commit purely by `sha` and writes the forged `success` status onto it - see [3](#0-2) , with no check that the commit belongs to `org-a`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
