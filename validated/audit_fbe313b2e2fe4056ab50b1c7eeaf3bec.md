### Title
Global, repository-unscoped commit status forgery via optional webhook signature verification - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a signature purely from the attacker-controlled payload field `repository.owner.login` (or `organization.login`), and `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever no `webhook_secret` is configured for that organization — which is the value shown in every shipped example/template config. Once past this optional gate, `StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)`, a completely global query with no repository or organization scoping, unlike `PushHandler`/`CheckSuiteHandler` which correctly filter through `stacks` (repository-scoped). This breaks the binding: organization whose (possibly absent) secret authenticated the request ≠ the repository/stack whose commit status is actually written.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb#L24-L38` computes the signing organization exclusively from the JSON body: [1](#0-0) 
and `repository_owner` is taken straight from the same attacker-supplied payload: [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` when no secret is configured: [3](#0-2) 

Every shipped configuration example (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`, `template.rb`, `docs/setup.md`) documents `webhook_secret` as optional and defaults it to nil: [4](#0-3) 

Once the request passes this check, `StatusHandler#process` resolves target commits with no repository/organization scoping at all: [5](#0-4) 

Contrast this with the correctly-scoped `PushHandler` and `CheckSuiteHandler`, which restrict to `stacks` derived from `payload.dig('repository', 'full_name')`: [6](#0-5) [7](#0-6) 

So even if an operator configures a webhook secret for their own organization, `Shipit.github(organization: repository_owner)` in `verify_signature` is selected by an attacker-controlled `repository.owner.login`/`organization.login` field independent of the sha the `StatusHandler` will actually act on. Any org name for which no `webhook_secret` is set (the documented default) makes signature verification a no-op, and the subsequently invoked `StatusHandler` writes a forged CI status onto **any** commit sha in the entire installation, in any stack belonging to any organization, because `Commit.where(sha: params.sha)` performs no repository/organization filtering.

### Impact Explanation
Forging a `status` webhook lets an unauthenticated attacker create a `Status` record for an arbitrary commit sha (`Status.replicate_from_github!`/`Commit#create_status_from_github!`). Status creation is not cosmetic — `Status` enables CI on the stack and schedules continuous delivery, and `Commit#add_status` schedules merges when a status becomes `pending`/`success`: [8](#0-7) [9](#0-8) 
This can be used to fake a green CI status on a commit belonging to a stack the attacker has no relationship with, unblocking `ci.require`d checks and triggering an unauthorized deploy/merge — matching the Critical "unauthorized deploy, rollback or merge" impact category, achieved purely by knowledge of a target commit sha with no valid GitHub credential.

### Likelihood Explanation
This does not require compromising anyone's webhook secret: leaving `webhook_secret` unset is the documented, common configuration (every example/template in the repo ships it as nil), so verification for that org's requests is unconditionally `true`. The attacker only needs a `repository.owner.login` matching a configured-but-secret-less org (or any org name causing an unhandled/permissive path) and a target commit sha, both easily obtainable from public GitHub activity or Shipit's own UI. No authentication, `ApiClient` token, or repository write access is needed.

### Recommendation
- Scope every webhook handler (especially `StatusHandler`) to the repository/stack derived from the verified payload's `repository.full_name`, mirroring `PushHandler`/`CheckSuiteHandler`, instead of matching commits globally by `sha`.
- Require `webhook_secret` to be present for every configured GitHub App/organization, and reject (422) webhooks for organizations with no secret configured rather than treating it as an implicit bypass.
- Bind the organization used to select the verification secret to the same repository object subsequently used by the handler, so a mismatched `repository.owner.login` vs. `repository.full_name` cannot pass verification while affecting a different repository.

### Proof of Concept
1. Configure/observe a Shipit instance where organization `AttackerOrg` (or any org) has no `webhook_secret` set (the shipped default).
2. Find any tracked commit `sha` for a target stack belonging to a different, unrelated organization (e.g. via the public Shipit UI or GitHub).
3. POST to `/webhooks` with header `X-Github-Event: status`, no valid `X-Hub-Signature` needed, and body:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/forged",
  "repository": {"owner": {"login": "AttackerOrg"}, "full_name": "attacker/irrelevant-repo"}
}
```
4. `verify_signature` resolves `Shipit.github(organization: "AttackerOrg")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` regardless of payload/signature.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` and creates a `success` status on the victim commit, in a completely unrelated stack, enabling CI-gated deploy/merge flows to proceed without genuine CI.

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
