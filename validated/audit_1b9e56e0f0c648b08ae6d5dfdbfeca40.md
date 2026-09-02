### Title
Cross-organization commit-status forgery via mismatched HMAC-authenticated organization and event-processed repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App configuration (and thus the HMAC `webhook_secret`) used to authenticate an inbound webhook based on `repository_owner`, a value read straight out of the untrusted, attacker-suppliable JSON body via `params.dig('repository', 'owner', 'login')` with a fallback to `params.dig('organization', 'login')`. Once the signature check passes, `WebhooksController#create` dispatches the very same JSON body to event handlers (`Shipit::Webhooks::Handlers::Handler#repository_name`, e.g. `StatusHandler`, `PushHandler`, `CheckSuiteHandler`) which instead key their side effects off `payload.dig('repository', 'full_name')`. There is no requirement that `repository.full_name` be owned by `repository_owner`. When a Shipit instance is configured to serve multiple GitHub organizations (a documented, supported configuration), an attacker who can obtain a valid signature for *any one* of the configured organizations (including one with an empty/blank `webhook_secret`, which `GitHubApp#verify_webhook_signature` treats as automatically verified) can craft a payload whose `repository.owner.login` matches that low-security organization while `repository.full_name` names a stack belonging to a different, victim organization tracked by the same Shipit instance.

### Finding Description
- Signature verification binds trust to `repository_owner`: [1](#0-0) [2](#0-1) 
- The GitHub App config (and its `webhook_secret`) is looked up per-organization, and if that organization's secret is blank the signature check is unconditionally satisfied: [3](#0-2) 
- After the (org-scoped) signature check passes, the controller re-parses the same raw body and fans it out to handlers with no re-validation that the acted-upon repository belongs to the verified organization: [4](#0-3) 
- Handlers derive the actual target repository/stack from a *different* JSON field, `repository.full_name`, which is never cross-checked against `repository.owner.login`/`repository_owner`: [5](#0-4) 
- `StatusHandler` uses this repository-agnostic lookup path to write a fabricated commit status for any commit matching the attacker-chosen `sha`, taking `state`, `description`, `target_url`, `context` verbatim from the payload: [6](#0-5) 
- `PushHandler` and `CheckSuiteHandler` similarly act on stacks resolved solely from `repository.full_name`: [7](#0-6) [8](#0-7) 
- Multi-organization hosting, where each org has its own independently configured `webhook_secret` (including the documented option of leaving it blank), is an explicitly supported and documented configuration: [9](#0-8) 

The equality that should hold — "the organization whose secret authenticated this request" == "the organization that owns the repository the handlers act upon" — is broken. The signature only proves the payload was signed with the secret associated with `repository.owner.login` (or `organization.login`); it says nothing about `repository.full_name`, which can point at any repository/stack hosted on the same Shipit instance, including ones belonging to a different organization.

### Impact Explanation
This crosses an authentication/authorization boundary between organizations hosted by the same Shipit instance: a request cryptographically tied to organization A's webhook credential (or to an organization with no configured secret) is used to mutate state belonging to organization B's stacks. Concretely:
- `StatusHandler` allows forging arbitrary CI/commit statuses (`state`, `description`, `context`, `target_url`) for commits in a victim organization's tracked repositories, which can be used to make the merge queue and deploy safety checks (`MergeRequest#all_status_checks_passed?`, `any_status_checks_failed?`) believe CI passed when it did not — enabling an unauthorized merge or deploy for a stack the attacker has no legitimate relationship with.
- `PushHandler`/`CheckSuiteHandler` allow triggering sync/refresh jobs against a victim organization's stacks from a request never actually sent by GitHub for that repository.

This matches the "unauthorized deploy/merge" and "escalation across the deployment-trust boundary" severity class described in scope, since the write happens on a repository/stack the authenticating organization does not own.

### Likelihood Explanation
Exploitability depends entirely on the operator's configuration: it requires (a) the Shipit instance to be configured for multiple GitHub organizations (a documented supported setup) and (b) at least one configured organization to have a blank/weak `webhook_secret`, or the attacker otherwise possessing a valid secret for any one hosted organization. Given the explicit "Webhook secret (optional)" guidance in the setup docs and the multi-org example, this is a plausible operational configuration rather than a purely theoretical one, but it is conditioned on host configuration choices that are within the documented, supported feature set (not a misuse of the engine).

### Recommendation
When dispatching a verified webhook to handlers, re-verify that `repository.full_name` (and/or `organization.login`) in the payload is actually owned by the organization whose secret verified the signature (`repository_owner`), rejecting the request otherwise. Do not allow `Handler#repository_name`/`stacks` resolution to operate on a repository whose owner differs from the authenticated organization.

### Proof of Concept
1. Operator configures Shipit for two organizations, e.g. `sandbox-org` (with `webhook_secret: nil`, matching the documented "optional" secret) and `victim-org` (properly secured), each tracking their own stacks.
2. Attacker sends `POST /webhooks` with header `X-Github-Event: status` and no/invalid `X-Hub-Signature`, and a body:
```json
{
  "sha": "<real sha of a commit on a victim-org tracked stack>",
  "state": "success",
  "context": "continuous-integration/travis-ci/push",
  "repository": { "owner": { "login": "sandbox-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "sandbox-org")`; because `sandbox-org`'s `webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of signature.
4. `create` dispatches the same payload to `StatusHandler`, which resolves the target commit purely by `sha` (no organization scoping) via `Commit.where(sha: params.sha)` and creates a forged success status, independent of `sandbox-org` vs `victim-org`.
5. The forged status can satisfy `MergeRequest#all_status_checks_passed?`/CI gating for `victim-org`'s stack, enabling an unauthorized merge/deploy. [10](#0-9)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/merge_request.rb (L193-202)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
```
