### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on the independently-controlled `repository.full_name` field, allowing cross-repository writes across GitHub Apps - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` verifies the inbound HMAC using `repository_owner`, a value read from the same untrusted JSON body it is about to verify. Once the signature check passes, every webhook `Handler` (`PushHandler`, `PullRequest::ClosedHandler`, etc.) resolves the target `Stack`/`Repository` using a *different* field of the same payload — `repository.full_name` — which is never cross-checked against the field that selected the signing secret. In a multi-organization Shipit deployment (documented in `docs/setup.md`, "Using Multiple Github Applications"), each GitHub org has its own independently configured `webhook_secret`. An attacker who legitimately controls one onboarded organization's GitHub App secret can forge a payload where `repository.owner.login` names their own org (so the correct secret is used and the signature check passes) while `repository.full_name` names a victim organization's repository, causing the handler to act on stacks it does not own.

### Finding Description
`verify_signature` computes the verifying app as: [1](#0-0) 
using `repository_owner`: [2](#0-1) 

The per-organization app/secret lookup is implemented in `Shipit.github`/`GitHubApp#verify_webhook_signature`: [3](#0-2) 
and `lib/shipit.rb`'s `github_app_config`, confirming distinct secrets per organization key in `secrets.yml`, as documented for multi-org setups: [4](#0-3) 

Once `verify_signature` succeeds, the raw JSON is dispatched to handlers unchanged: [5](#0-4) 

Every handler resolves target scope from a *different* payload field, `repository.full_name`, with no re-validation against `repository.owner.login`: [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` simply splits and looks up by owner/name from that string: [8](#0-7) 

Because the HMAC covers the raw request body bytes chosen entirely by the sender, and the field used to pick the *secret* (`repository.owner.login`) is independent of the field used to pick the *target* (`repository.full_name`), an attacker who is a legitimate admin of one onboarded org (org A, with its own `webhook_secret`) can build a payload with `"repository": {"owner": {"login": "org-a"}, "full_name": "org-b/victim-repo", ...}`, sign it with org A's secret, and have it processed as if it originated from org B's repository.

This is the same class of bug as the referenced report: the field the protocol/engine authorizes on (`admin`/`repository_owner`) is not the field the state-changing action actually operates on (`wooracle.authority` created unchecked / handler target `repository.full_name`).

### Impact Explanation
Handlers that resolve scope purely from `full_name`/branch, without any tie back to the verified organization, allow an attacker with only their own onboarded org's webhook credentials to:
- Force a git sync against arbitrary victim stacks via `PushHandler#process`, which calls `stack.sync_github(expected_head_sha:)`: [9](#0-8) 
  — on stacks with `continuous_deployment` enabled this can trigger deploy behavior on a repository the attacker doesn't control.
- Archive victim review stacks via `PullRequest::ClosedHandler#process` using an attacker-forged `pull_request`/`repository.full_name` combination: [10](#0-9) 
- Inject fabricated commit statuses for arbitrary commit SHAs, since `StatusHandler` looks up `Commit.where(sha:)` globally with no repository scoping at all: [11](#0-10) 
- Trigger check-run refresh jobs on victim stacks via `CheckSuiteHandler`: [12](#0-11) 

This constitutes cross-repository writes and can lead to an unauthorized deploy (via forced sync + continuous deployment), matching the "Critical" impact bar (cross-repository writes / unauthorized deploy).

### Likelihood Explanation
Requires the attacker to be an authorized administrator of at least one GitHub organization already onboarded into a multi-org Shipit deployment (able to configure/know that org's own `webhook_secret`) — a credential boundary the attacker legitimately holds for their own org, but which is being reused to write to a different org's stacks. This matches the documented multi-tenant configuration pattern in `docs/setup.md`, so the precondition is realistic for any Shipit instance serving more than one organization.

### Recommendation
After successfully verifying the signature, re-derive `repository_owner`/organization strictly from the same field the handlers use (`repository.full_name`'s owner segment, or `organization.login`) and reject the request if the field used for signature selection does not match the field used for repository targeting. Alternatively, thread the verified organization identity through to each `Handler` and have `stacks`/`repository` resolution assert that the resolved `Repository#owner` equals the verified organization, rejecting mismatches (`head(422)`), and scope `StatusHandler`'s `Commit` lookup to stacks under the verified repository rather than a global `Commit.where(sha:)` query.

### Proof of Concept
1. Deploy Shipit with two onboarded organizations, `org-a` and `org-b`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` multi-app config).
2. As an administrator of `org-a` only, know `org-a`'s `webhook_secret`.
3. Craft a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
4. Compute `X-Hub-Signature: sha1=<hmac(org-a-secret, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` to `"org-a"`, uses `org-a`'s secret, and the signature matches → request proceeds.
6. `PushHandler#process` resolves `stacks` via `Handler#repository_name` = `payload.dig('repository','full_name')` = `"org-b/victim-repo"`, matches stacks belonging to `org-b`'s repository, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on a repository the attacker does not own.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
