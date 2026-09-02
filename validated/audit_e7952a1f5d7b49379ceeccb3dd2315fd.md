This confirms `Repository.from_github_repo_name` looks up by `owner`/`name` parsed independently from `params.repository.full_name`, which is a JSON field entirely distinct from `params.repository.owner.login` used in signature verification. The attacker fully controls both fields in the forged webhook body, so they can decouple them.

### Title
Attacker can archive/mutate any repository's ReviewStack via `pull_request closed` webhook using an unrelated no-secret organization's identity to bypass signature verification - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` used for HMAC verification based solely on `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) . `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization's config has no `webhook_secret` [3](#0-2) . Because `params.repository.owner.login` (used to select the verifying app) and `params.repository.full_name` (used later by `ClosedHandler` to resolve the actual `Repository`/`ReviewStack`) are independent, attacker-controlled JSON fields, an attacker can name a "no-secret" org in the former while targeting an arbitrary victim repository's `full_name` in the latter.

### Finding Description
The broken binding is the implicit assumption: `repository_owner used to verify signature == repository that owns the affected ReviewStack`. In code, these are two separate reads of the same JSON payload:

- `repository_owner` (signature selection) = `params.dig('repository','owner','login')` [2](#0-1) 
- `repository` (mutation target) = `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, which independently parses `owner/name` out of `full_name` and does an exact `find_by` [4](#0-3) [5](#0-4) .

Nothing in the request enforces that `repository.owner.login == full_name.split('/').first`. An attacker who knows (or discovers) that some configured GitHub org `no-secret-org` has a blank `webhook_secret` in `Shipit.github`'s config can craft:

```json
{
  "action": "closed",
  "number": 42,
  "pull_request": { ... },
  "repository": { "owner": { "login": "no-secret-org" }, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```

`verify_signature` calls `Shipit.github(organization: "no-secret-org")`, whose `verify_webhook_signature` short-circuits to `true` because `webhook_secret` is blank, regardless of the `X-Hub-Signature` header content or absence [6](#0-5) . The request then reaches `ClosedHandler#process`, which resolves `repository` from `full_name` = `"victim-org/victim-repo"` and calls `review_stack.archive!` on the real `ReviewStack` for PR #42 in that victim repository [7](#0-6) . `ReviewStackAdapter#archive!` deprovisions and archives the actual stack, unconditionally, once found [8](#0-7) .

No existing guard prevents this: `verify_signature` never cross-checks `full_name`'s owner against the org used for verification; `ClosedHandler`'s `ExplicitParameters` schema only requires `repository.full_name` to be a `String`, with no format/consistency validation against `repository.owner.login` [9](#0-8) .

Regarding the `continuous_deployment` amplification claimed in the question: `ClosedHandler` only calls `archive!`, which deprovisions/archives the stack — it does not itself trigger a deploy or `ContinuousDeliveryJob`. The archive action stops future auto-deploys on that stack rather than causing one. The primary, directly demonstrable impact is unauthorized archival/deprovisioning of a victim `ReviewStack` cross-tenant, not an unauthorized deploy caused by this specific handler.

### Impact Explanation
This lets an unprivileged attacker who owns/controls a completely unrelated, no-secret-configured GitHub organization forge a `pull_request` `closed` event that archives and deprovisions a **victim** repository's review stack for an arbitrary PR number, without ever authenticating to that victim repository's webhook secret. This is a real cross-tenant write: "a payload for one repository mutating another's stack," matching the Critical impact category in the rules (unauthorized action on a repository/stack that did not authenticate the request). It is repeatable against any PR number/any repository as long as any org in the Shipit install lacks a `webhook_secret`, and the same class of attack (owner/full_name decoupling) is not limited to `ClosedHandler` — `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `EditedHandler`, `AssignedHandler`, `LabelCapturingHandler` follow the identical pattern of resolving `repository` from `full_name` independent of the signature-selecting `owner.login`.

### Likelihood Explanation
Preconditions: (1) at least one GitHub organization configured in Shipit's multi-org `github:` secrets section with a blank/absent `webhook_secret` (explicitly supported/documented configuration, see `docs/setup.md` "Using Multiple Github Applications" and example secrets files showing `webhook_secret: # nil`), and (2) a victim stack/review-stack with `review_stacks_enabled`/an existing PR-bound `ReviewStack`. Attacker cost is a single unauthenticated HTTP POST to `/webhooks` with a crafted JSON body; no secrets, sessions, or GitHub API access are required. This is fully repeatable and requires no live GitHub interaction to demonstrate in a controlled test.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, and/or in each `PullRequest` handler, enforce that the organization used to verify the webhook signature matches the owner encoded in `repository.full_name` before any handler is invoked (e.g., reject if `params.dig('repository','owner','login') != params.dig('repository','full_name').split('/').first`). Additionally, treat a blank `webhook_secret` as a misconfiguration to warn/fail loudly on, rather than silently trusting unsigned payloads.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` style, illustrative — actual file is out of scope per rules but demonstrates the equality check):
1. Configure two orgs in `Shipit.github` config: `"no-secret-org"` with `webhook_secret: nil`, and `"victim-org"` with a real `webhook_secret`.
2. Create `Repository` with `owner: "victim-org", name: "victim-repo"`, and a `ReviewStack` bound to PR number 42, not archived, `continuous_deployment: true`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no valid `X-Hub-Signature` (or an arbitrary bogus one), body:
   `{"action":"closed","number":42,"pull_request":{...},"repository":{"owner":{"login":"no-secret-org"},"full_name":"victim-org/victim-repo"},"sender":{"login":"attacker"}}`.
4. Assert response is `200`/`:ok` (not `422`).
5. Assert (equality before/after): before, `ReviewStack.find_by(environment: "pr42").archived?` is `false`; after the request, reload and assert it is now `true` — i.e. `repository_owner_used_for_auth ("no-secret-org") != repository.full_name owner ("victim-org")` yet the victim's stack was mutated, proving the binding is broken.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-59)
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

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```
