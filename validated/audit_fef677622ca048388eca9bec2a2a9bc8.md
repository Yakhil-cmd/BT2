### Title
Webhook signature check keys off `repository.owner.login`/`organization.login` while every event handler resolves the target repository from the independent `repository.full_name` field, letting a signature valid for an unsecured organization authorize writes to any other organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App / `webhook_secret` to validate the HMAC against using `repository_owner`, a value read from the *same* untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Every downstream event handler, however, ignores that value entirely and resolves the actual `Repository`/`Stack` to mutate using a different top-level field of the same body: `params.repository.full_name`. Nothing enforces that these two independently-chosen fields refer to the same organization. Combined with `GitHubApp#verify_webhook_signature` returning `true` unconditionally when an organization has no `webhook_secret` configured, an attacker only needs to know of *one* Shipit-tracked GitHub organization without a configured secret to forge webhook events against *any other* organization's repositories tracked by the same Shipit instance.

### Finding Description
`verify_signature` selects the app/secret to check against solely from the payload: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` trivially passes when that organization's `webhook_secret` is blank: [3](#0-2) 

Meanwhile, the actual event handlers that mutate state (create/archive stacks, sync pull requests, etc.) resolve their target repository from a *separate* field, `repository.full_name`, with no cross-check against the value used for signature verification: [4](#0-3) [5](#0-4) [6](#0-5) 

Because `repository.owner.login`/`organization.login` (used to choose the verification secret) and `repository.full_name` (used to choose the target repository) are two unrelated fields inside the same attacker-controlled JSON body, the binding "organization whose signature was authenticated" == "repository that gets written" is never enforced. An attacker who knows of any org onboarded into this Shipit instance without a `webhook_secret` (or with a leaked/misconfigured one, which is not required here — the *unsecured* org path is enough) can:

1. Set `repository.owner.login` / `organization.login` to the unsecured org so `verify_signature` passes unconditionally (`return true unless webhook_secret`).
2. Set `repository.full_name` to `victim-org/victim-repo`, a fully unrelated org that *does* have a properly configured secret and active stacks.
3. Send any `X-Github-Event` (`push`, `pull_request`, `status`, etc.) with a forged payload; the controller accepts it because signature verification never inspects `repository.full_name`, and the handler happily acts on `victim-org/victim-repo`.

This is precisely the "organization that authenticated versus the repository that is written" trust-binding break: the signature only ever authenticates knowledge of *an* organization's secret (or exploits the absence of one), never the specific repository the payload claims to describe.

### Impact Explanation
This allows an unauthenticated, unprivileged internet attacker (no `ApiClient` token, no GitHub App key, no Shipit session) to inject forged GitHub webhook events against a targeted organization's repositories, as long as at least one other organization configured in the same Shipit instance lacks a `webhook_secret`. Concretely reachable handlers include the pull-request family (create/archive review stacks, capture labels, edit tracked PR metadata) and, by the same `full_name`-based resolution pattern used throughout `app/models/shipit/webhooks/handlers/**`, the `status` handler that records CI statuses used to gate deploy eligibility (`deployable?`/`required_statuses`). Forging a passing CI status for a commit in a targeted repository can make an otherwise non-deployable commit appear deployable, enabling an unauthorized deploy — meeting the "unauthorized deploy" Critical-impact bar.

### Likelihood Explanation
Medium: it requires the operator of the Shipit instance to have onboarded at least one GitHub organization/app without a `webhook_secret` set (plausible in multi-tenant/dev/staging setups, or during incremental onboarding), and requires no other credential or privileged access. The `repository_owner` and `repository.full_name` fields are both freely attacker-controlled in the raw POST body, so once the precondition holds, exploitation is trivial (a single crafted HTTP POST).

### Recommendation
Bind signature verification to the same identity that handlers use to resolve state: verify the HMAC using the secret configured for the organization derived from `repository.full_name` (not a separately-read `repository.owner.login`/`organization.login`), and reject payloads where these fields disagree. Additionally, do not treat a missing `webhook_secret` as "verification passed" (`return true unless webhook_secret` in `lib/shipit/github_app.rb`); instead require an explicit opt-in/allow-list for secret-less organizations, or reject webhooks for organizations with no configured secret.

### Proof of Concept
1. Assume Shipit is configured with organization `unsecured-org` (no `webhook_secret` in its GitHub app config) and organization `victim-org` (has a proper `webhook_secret`, has tracked repository `victim-org/victim-repo`).
2. POST to `/webhooks` (route mounted for `Shipit::WebhooksController#create`) with header `X-Github-Event: pull_request` and body:
```json
{
  "action": "opened",
  "number": 1,
  "pull_request": { "id": 1, "number": 1, "url": "...", "title": "x", "state": "open",
    "additions": 1, "deletions": 0,
    "head": { "sha": "deadbeef", "ref": "attacker-branch" },
    "user": { "login": "attacker" }, "assignees": [], "labels": [] },
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "unsecured-org" } },
  "organization": { "login": "unsecured-org" },
  "sender": { "login": "attacker" }
}
```
No `X-Hub-Signature` header (or any garbage value) is required.
3. `verify_signature` computes `repository_owner` = `"unsecured-org"` (`app/controllers/shipit/webhooks_controller.rb:59-62`), looks up `Shipit.github(organization: "unsecured-org")`, and `verify_webhook_signature` returns `true` unconditionally because that org has no `webhook_secret` (`lib/shipit/github_app.rb:76-77`).
4. `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#process` runs and resolves the target repository via `params.repository.full_name` = `"victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54`), creating/mutating a review stack under `victim-org` despite the signature only ever having been checked against `unsecured-org`'s (non-existent) secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-65)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```
