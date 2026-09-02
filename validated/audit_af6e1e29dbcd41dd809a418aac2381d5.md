### Title
Webhook signature validated against attacker-controlled organization while payload actions apply to an unrelated repository/stack - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
The bug class in the external report is "the contract acts on unverified/unbound state (accumulated fees) while trusting a value it never actually reconciled against the true committed state." The structural analog in `shipit-engine` is in the GitHub webhook pipeline: the field used to select *which* HMAC secret verifies the signature (`repository.owner.login`, from the org that "authenticates" the request) is not bound to the field later used to select *which* repository/stack the payload's action is applied to (`repository.full_name`, resolved via `Repository.from_github_repo_name`). Both come from the same unverified JSON body, and the engine never asserts `full_name == "#{owner.login}/#{name}"` before trusting either value independently for a different purpose.

### Finding Description
`WebhooksController#verify_signature` derives the organization used to look up the webhook secret purely from attacker-supplied payload data, before the signature has been checked: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')`. The HMAC is computed with `Shipit.github(organization: repository_owner).verify_webhook_signature`, i.e., the secret used to validate the payload is chosen by an attacker-controlled field inside the very payload being validated: [3](#0-2) 

Separately, every handler resolves the target `Stack`/`Repository` to act on using a *different* field from the same unverified payload — `repository.full_name` — via `Repository.from_github_repo_name`: [4](#0-3) [5](#0-4) 

Nothing in the controller or in `Handler` enforces that `repository.full_name` is consistent with `repository.owner.login` (e.g., `full_name == "#{owner.login}/#{name}"`). An attacker who legitimately owns/administers a GitHub App installation on their **own** organization (`attacker-org`) knows that organization's `webhook_secret` (configured by them in their own app settings) and can therefore produce a valid `X-Hub-Signature` for any payload body, as long as `repository.owner.login` (or, in its absence, `organization.login`) in that body is set to `attacker-org`. Because `full_name` is an independent string field, the attacker can set it to `victim-org/victim-repo` while keeping `owner.login: attacker-org` to pass signature verification, e.g. for the `push`, `status`, and `check_suite` handlers: [6](#0-5) [7](#0-6) [8](#0-7) 

The binding that should hold (and is broken) is:

`organization that authenticated the request (owner.login used for webhook_secret lookup) == repository whose Stack/Commit state is written (full_name used to resolve Repository/Stack)`

Before the attack: for legitimate GitHub-originated payloads, GitHub always sets `repository.owner.login` and `repository.full_name` consistently, so the equality trivially holds.

After the attack: an attacker with their own GitHub App installation (and hence knowledge of their own `webhook_secret`) crafts a JSON body where `owner.login = attacker-org` (satisfies signature check) but `full_name = victim-org/victim-repo` (drives which `Stack` is mutated), breaking the equality while still passing `verify_signature`.

### Impact Explanation
Via `StatusHandler`, the attacker can inject a forged commit status (e.g., `state: success`) for any commit SHA on a stack belonging to a repository the attacker does not control, as long as they can guess/know a SHA tracked by Shipit (SHAs are public git history, not secret). Shipit's merge queue and continuous-delivery safety checks rely on commit statuses/check-suites to decide whether a commit is deployable/mergeable, so forging a passing status for a victim repository's commit is a step toward an unauthorized/unsafe deploy or merge decision without ever touching the victim's actual GitHub App credentials. `PushHandler`/`CheckSuiteHandler` similarly let the attacker trigger `sync_github`/`schedule_refresh_check_runs!` against a victim stack cross-repository, which is at minimum an unauthorized cross-repository interaction with another team's `Stack` state.

### Likelihood Explanation
Exploitation requires the attacker to control a legitimate GitHub App installation and its `webhook_secret` for at least one organization already onboarded to the same Shipit instance (multi-tenant deployments configure `Shipit.github` per organization). This is a plausible unprivileged-attacker position in a multi-org Shipit deployment: creating/controlling one's own GitHub org and installing the same GitHub App type does not require any Shipit-side credentials, session, or repository write access to the victim's actual repo — only knowledge of the shared `POST /webhooks` endpoint. The forged `full_name` field is trivial to set since it is just JSON text with no server-side consistency check against `owner.login`.

### Recommendation
- In `WebhooksController#verify_signature` / `Handler`, derive the "acting" repository strictly from the same object whose owner was used to select the verification secret, and reject the payload if `repository.full_name` does not match `"#{repository.owner.login}/#{repository.name}"`.
- Alternatively (defense in depth), after resolving the target `Stack`/`Repository` via `full_name`, re-verify that `Repository#owner` equals the `repository_owner` value that was used to select the webhook secret, before invoking any handler logic that mutates that stack's state.

### Proof of Concept
1. Attacker creates GitHub organization `attacker-org` and installs a GitHub App on it, configuring `webhook_secret = "s3cr3t"` (fully within the attacker's control; this app targets their own Shipit-integrated org).
2. Attacker crafts a JSON payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1("s3cr3t", body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, loads `attacker-org`'s `webhook_secret`, and the signature verifies successfully (per `GitHubApp#verify_webhook_signature`, `lib/shipit/github_app.rb:76-83`).
5. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) looks up `Commit.where(sha: params.sha)` — commits belonging to `victim-org/victim-repo`'s stack — and calls `create_status_from_github!`, writing a forged status onto the victim repository's commit despite the request only being authenticated as `attacker-org`.

*Note: I was not able to independently trace every downstream consumer of a `Commit`'s status (e.g., exact merge-queue gating logic in `app/models/shipit/merge_request.rb` / `status/group.rb`) within the tool-call budget available, so the precise blast radius of a forged "success" status (whether it can, by itself, unblock a real merge/deploy versus only corrupt displayed CI state) could not be fully confirmed and should be verified directly against `app/models/shipit/status/group.rb` and `app/models/shipit/merge_request.rb`.*

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
