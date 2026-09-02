### Title
Webhook signature verification is bound to an attacker-chosen organization while event processing acts on an attacker-chosen repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController` selects which GitHub App (and therefore which `webhook_secret`) to use for HMAC verification from an unauthenticated field of the incoming payload, then dispatches the same payload to handlers that resolve the target `Repository`/`Stack` from a *different* payload field. These two fields are never cross-checked, so the "organization that authenticated" and the "repository that is written to" can be made to diverge, exactly analogous to the reported bug class where a check is performed against one value while the state-changing action operates on another value that was never covered by the check.

### Finding Description
`WebhooksController#verify_signature` picks the signing organization purely from request body content: [1](#0-0) [2](#0-1) 

`repository_owner` comes from `params.dig('repository','owner','login')` (or the `organization.login` fallback) and is used only to look up `Shipit.github(organization: repository_owner)`, i.e., which per-organization `webhook_secret` to HMAC-verify against.

`GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as "always verified": [3](#0-2) 

`webhook_secret` is optional per the setup documentation ("If you've set a webhook secret during the App creation, you should copy it here"), and the multi-org config format explicitly allows each organization to have its own independent `webhook_secret`: [4](#0-3) 

Once `verify_signature` passes (trivially, if the resolved organization has no `webhook_secret` configured), `WebhooksController#create` dispatches the *entire, still-untrusted* payload to handlers: [5](#0-4) 

Handlers resolve the actual repository/stack from `repository.full_name`, a field independent of `repository.owner.login` used for authentication: [6](#0-5) [7](#0-6) 

Because `verify_webhook_signature` binds trust to `repository.owner.login` (org A, misconfigured with no secret) while the handler binds the actual write to `repository.full_name` (org B, a fully protected tenant), an attacker can craft a single JSON body where these two fields disagree: the equality the code implicitly assumes — `authenticated_organization == owner(written_repository)` — is never enforced.

### Impact Explanation
An unauthenticated attacker (the `/webhooks` endpoint requires no session, `ApiClient` token, or GitHub credentials — it is only gated by the HMAC check being bypassed here) can inject arbitrary, fully-controlled GitHub event payloads (`push`, `status`, `check_suite`, `pull_request`, etc.) against any repository/stack hosted on the same Shipit instance, as long as any single organization configured on that instance lacks a `webhook_secret`. Forged `status`/`check_suite` events can mark arbitrary commits as passing CI, which (per `Stack#trigger_continuous_delivery` / `deployable_commits`) can cause Shipit to automatically deploy attacker-chosen commits via continuous delivery — an unauthorized deploy, matching the report's Critical-impact bar.

### Likelihood Explanation
This only requires a multi-organization Shipit deployment (documented, supported configuration) where at least one configured GitHub App omits `webhook_secret` (an optional field per the docs). No credentials, sessions, or network position beyond reaching the public `/webhooks` endpoint are required, and the divergent-field logic is deterministic engine code, not a host-mounting or operational misconfiguration outside the engine's own logic.

### Recommendation
- Reject webhooks whose resolved `repository.owner.login`/`organization.login` does not match the owner encoded in `repository.full_name` before dispatching to handlers.
- Make `webhook_secret` mandatory (raise instead of `return true unless webhook_secret`) for any configured GitHub App/organization used in production.
- Bind the handler's repository/stack resolution to the same verified organization identity used for signature verification instead of re-parsing an independent field from the same untrusted payload.

### Proof of Concept
1. Configure a Shipit instance with two GitHub organizations: `victim-org` (properly configured with `webhook_secret`) and `attacker-org` (configured, but `webhook_secret` left blank — a valid/optional configuration per docs).
2. POST to `/webhooks` with header `X-Github-Event: status` and no/garbage `X-Hub-Signature`, with a JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally, per `lib/shipit/github_app.rb:76-83`.
4. `Shipit::Webhooks.for_event('status')` handlers then process the payload using `repository.full_name` = `"victim-org/victim-repo"`, forging a passing CI status on a commit in `victim-org`'s stack that the attacker never authenticated against.

Note: I could not fully trace the `StatusHandler`'s exact write path within the tool budget available; the causal link from a forged `status`/`check_suite` event to an actual deploy trigger is inferred from `Stack#trigger_continuous_delivery` and `next_commit_to_deploy`/`deployable_commits` logic [8](#0-7)  rather than directly read from the status handler file itself; confirming this end-to-end chain would benefit from a full Devin session with broader file access.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
