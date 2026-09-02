### Title
Webhook signature verification authenticates the wrong organization, allowing forged `status`/`push` events to trigger unauthorized deploys - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to verify a webhook against using an attacker-controlled field of the *same, unverified* JSON body (`repository.owner.login`, or `organization.login` as fallback), rather than using the field the handlers actually act on (`repository.full_name`). Combined with `GitHubApp#verify_webhook_signature` returning `true` whenever no `webhook_secret` is configured for that organization, an unprivileged attacker can pick any GitHub App entry in `Shipit.secrets.github` that has a blank `webhook_secret`, put that org's name in `repository.owner.login`, and put the name of a *different, fully-secured* tracked repository in `repository.full_name`. The signature check trivially passes for the "authenticating" organization while the payload is processed against the unrelated target repository, breaking the intended binding `authenticated_organization == acted_upon_repository`.

### Finding Description
`verify_signature` computes the organization to check against from the raw JSON body before any authenticity is established: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` when the selected organization's `webhook_secret` is blank/unset: [3](#0-2) 

Meanwhile, every event handler determines *which repository/stack to mutate* from a completely separate field of the same untrusted body — `repository.full_name` — via `Handler#repository_name`: [4](#0-3) 

So the field used to select the verifying secret (`repository.owner.login`) and the field used to select the target of the action (`repository.full_name`) are independent, attacker-controlled strings within the same forged payload. In a multi-organization deployment (`config/secrets.yml` keyed by organization, as documented in `docs/setup.md`), if any configured organization has `webhook_secret` unset, an attacker can:
1. Set `repository.owner.login` to that unsecured organization's name (or set `organization.login` if `repository` is omitted, via the fallback in `repository_owner`), causing `verify_webhook_signature` to return `true` unconditionally.
2. Set `repository.full_name` (or `sha`, for `status` events) to reference a tracked stack belonging to an entirely different, properly-secured organization.

The forged event is then processed as authentic for that unrelated repository.

### Impact Explanation
This breaks a credential boundary: an organization "authenticating" the webhook is not the repository the engine writes to. Concretely:
- A forged `status` event with `state: "success"` for an arbitrary tracked commit `sha` is accepted by `StatusHandler#process`, creating a `Status` record via `Commit#create_status_from_github!`. `Status` triggers `schedule_continuous_delivery` on create, which can lead `ContinuousDeliveryJob` to call `Stack#trigger_continuous_delivery` → `trigger_deploy` for stacks with `continuous_deployment` enabled: [5](#0-4) [6](#0-5) 
- A forged `push` event similarly causes `PushHandler#process` to call `stack.sync_github` for the targeted repository's branches, independent of which org validated the signature: [7](#0-6) 

This can result in an unauthorized deploy being triggered for a repository the attacker has no access to, satisfying the "unauthorized deploy" impact category, with no session, `ApiClient` token, or GitHub write access required.

### Likelihood Explanation
Exploitability depends entirely on host configuration: it requires the Shipit instance to be configured with multiple GitHub Apps (per `docs/setup.md`'s "Using Multiple Github Applications" section) where at least one entry has no `webhook_secret` set (which the setup docs explicitly mark as `optional`), while other organizations' repositories are tracked and have `continuous_deployment` enabled. In such a (documented-as-valid) configuration, the attack requires only a single unauthenticated HTTP POST to `/webhooks` with no header requirements beyond `X-Github-Event`.

### Recommendation
- Verify the webhook signature using a secret that cannot be selected by attacker-controlled payload content, or require `webhook_secret` to be mandatory for all configured organizations (reject `nil`/blank secrets instead of returning `true`).
- After verifying the signature, cross-check that the repository referenced in the payload (`repository.full_name`) actually belongs to the organization whose secret verified the request before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `secured-org` (with `webhook_secret` set) tracking `secured-org/app`, and `unsecured-org` (with `webhook_secret` left blank, as the setup docs mark it optional) also installed.
2. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<sha of a commit on secured-org/app tracked in Shipit>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "unsecured-org" }, "full_name": "secured-org/app" }
}
```
No valid `X-Hub-Signature` header is needed since `Shipit.github(organization: "unsecured-org").verify_webhook_signature` returns `true` unconditionally (blank secret).
3. `WebhooksController#create` dispatches to `StatusHandler`, which creates a `success` `Status` for the commit under `secured-org/app`, potentially triggering an unauthorized deploy if `continuous_deployment` is enabled for that stack.

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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/stack.rb (L210-228)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
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
