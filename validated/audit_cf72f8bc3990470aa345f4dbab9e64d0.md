This confirms the multi-org scenario is a documented, supported deployment mode (`Shipit.github(organization:)` looks up per-organization webhook secrets, as shown in `test/dummy/config/secrets_double_github_app.yml`), which is exactly the setup where the binding break is exploitable.

### Title
Webhook Signature Verified Against Attacker-Controlled Organization While Handlers Act on a Different Payload-Supplied Repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to use for HMAC verification by reading `repository.owner.login` (or `organization.login`) directly out of the **unverified** request body, via `repository_owner`. [1](#0-0)  Once verification passes, `create` hands the same raw, attacker-controlled `params` hash to every registered handler, unmodified. [2](#0-1)  Handlers, however, resolve which `Stack`/`Repository` to mutate using a **different** field of the same payload: `repository.full_name`. [3](#0-2) 

### Finding Description
Shipit supports multi-tenant deployments where each onboarded GitHub organization has its own GitHub App and its own `webhook_secret`, as documented and covered in tests (`docs/setup.md` "Using Multiple Github Applications", `test/dummy/config/secrets_double_github_app.yml`). [4](#0-3)  `Shipit.github(organization:)` looks the App config up by organization name pulled straight from the request body. [5](#0-4) 

The binding that should hold is:
`organization whose secret authenticated the request == repository/organization that the payload is allowed to mutate`

In practice, the controller computes the authenticating organization from `params.dig('repository','owner','login')` (or `organization.login`), and verifies the raw body HMAC against **that** organization's secret only: [1](#0-0) . Nothing ties this same field to what the handlers subsequently act on. Every `Handler` subclass instead derives the target `Repository`/`Stack` from `repository.full_name` (or in some pull-request handlers, from `params.repository.full_name` directly), a separate, independently-controlled string inside the very same JSON body: [3](#0-2) , [6](#0-5) .

An attacker who legitimately administers one onboarded GitHub organization ("OrgAttacker", with a known `webhook_secret` — obtainable by any org admin who can view/rotate the GitHub App webhook secret for their own org's installation) can craft an arbitrary JSON body where:
- `repository.owner.login` = `"OrgAttacker"` — used only to pick the verifying secret,
- `repository.full_name` = `"OrgVictim/victim-repo"` — used by the handler to find the real `Stack`.

Because the HMAC is computed over the full raw body with `OrgAttacker`'s secret, `verify_webhook_signature` succeeds using a secret the attacker legitimately possesses: [7](#0-6) . The `create` action then dispatches the identical payload to `Shipit::Webhooks.for_event(event)` handlers, which look up `OrgVictim/victim-repo`'s `Stack` by `full_name` and act on it as if it were a genuine GitHub-signed event for that repository. [2](#0-1) 

This is exploitable for high-impact events: forging a `status` or `check_suite` event with `state: "success"` against a victim stack that has `continuous_deployment: true` will make `Commit#add_status` trigger `ContinuousDeliveryJob`, which calls `Stack#trigger_continuous_delivery` → `trigger_deploy`, causing an **unauthorized deploy** on a repository the attacker does not own. [8](#0-7) [9](#0-8) 

### Impact Explanation
This breaks the binding "organization that authenticated" vs "repository that is written" explicitly permitted in scope. It allows a cross-tenant, unauthorized action: an attacker controlling only their own onboarded org's webhook secret can trigger deploys, archive/unarchive review stacks, or manipulate pull-request/commit-status state on a victim organization's stack that they have no access to. Given that a forged status event can drive an unauthorized deploy on a victim's stack, this qualifies as Critical impact per the rules ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires the attacker to be an admin of at least one legitimately onboarded organization in a multi-org Shipit deployment (a supported, documented configuration) and to know that org's own `webhook_secret` — information any org owner configuring the GitHub App would ordinarily hold. No other credential, session, or GitHub write access to the victim organization is needed; the crafted HTTP POST to `/webhooks` is otherwise unauthenticated by GitHub itself, relying solely on this mismatched field selection.

### Recommendation
Bind verification to the exact repository/organization that handlers will subsequently act on:
- Verify using the same fully-qualified identifier (`repository.full_name`, not just `owner.login`) that handlers use to resolve the `Stack`/`Repository`.
- After verification, additionally check that the resolved `Repository.owner` matches the organization whose secret validated the signature, rejecting the request otherwise.
- Consider scoping each `GithubHook`/App config's accepted repositories explicitly rather than trusting payload-declared ownership fields.

### Proof of Concept
1. Shipit is configured with two organizations, `OrgAttacker` (secret known to attacker, who administers it) and `OrgVictim` (has a stack with `continuous_deployment: true`), per the multi-org config schema. [4](#0-3) 
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "OrgAttacker" }, "full_name": "OrgVictim/victim-repo" },
  "sha": "<head sha of OrgVictim/victim-repo>",
  "state": "success",
  "context": "ci/attacker-forged",
  "branches": [{ "name": "main" }]
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgAttacker_webhook_secret, raw_body)>` using their own known secret.
4. `WebhooksController#verify_signature` computes `repository_owner = "OrgAttacker"`, fetches `Shipit.github(organization: "OrgAttacker")`, and successfully verifies the signature against the attacker's own secret. [1](#0-0) 
5. `create` dispatches the payload to the `status` handler, which resolves the `Stack` via `repository.full_name = "OrgVictim/victim-repo"`, creates a passing `Status` on the victim's commit, and — since `continuous_deployment: true` — triggers an unauthorized deploy job for `OrgVictim`'s stack. [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L49-54)
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

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/stack.rb (L210-229)
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
    end
```
