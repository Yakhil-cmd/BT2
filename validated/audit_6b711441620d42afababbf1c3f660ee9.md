### Title
Webhook signature is bound to the wrong organization, letting a `status` event authenticated for one repository write commit state to a completely different repository — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/secret used to authenticate an inbound webhook by reading `repository.owner.login` (or `organization.login`) out of the *unverified* JSON body itself, then verifies the HMAC using that organization's `webhook_secret`.<cite repo="Jaredbentat/shipit-engine--019" path="app/controllers/shipit/webhooks_controller.rb" start="24,29" end="30,61" /> Once the signature check passes, `StatusHandler#process` applies the event to *every* `Commit` whose `sha` matches the payload, with no check that the commit belongs to the repository/organization that was actually authenticated: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [1](#0-0)  `CheckSuiteHandler` similarly resolves target stacks purely from `payload.dig('repository','full_name')`, a field never covered by the signature check, via `Handler#stacks`/`#repository_name`. [2](#0-1) 

### Finding Description
The binding that should hold is: *the organization whose secret validated the signature* == *the repository/commit that the handler is authorized to mutate*. In this engine, the two sides diverge:

- Signature verification is scoped by `repository_owner`, computed from the same untrusted payload before the signature is checked: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [3](#0-2) 
- `GitHubApp#verify_webhook_signature` explicitly treats a missing `webhook_secret` for that organization as an automatic pass: `return true unless webhook_secret`. [4](#0-3)  Shipit's own multi-org setup docs describe `webhook_secret` as optional per organization. [5](#0-4) 
- Once verification passes (for the org resolved from the payload), the actual handler that mutates state (`StatusHandler`) does not re-derive or re-check that the commit's owning repository/organization matches the one that was authenticated — it looks the commit up globally by `sha` across the whole instance. [1](#0-0) 

Consequently, in a Shipit deployment tracking multiple GitHub organizations (the multi-org config schema documented in `config/secrets.development.example.yml`), [6](#0-5)  any organization whose entry has no `webhook_secret` configured (an explicitly supported, documented state) becomes an open, unauthenticated relay: an attacker can POST a forged `X-Github-Event: status` webhook naming that org as `repository.owner.login`, pass `verify_signature` trivially, and supply an arbitrary `sha` belonging to a commit tracked under a *different*, secret-protected organization/stack in the same instance. `StatusHandler` will happily attach a fabricated `state: success` status to that unrelated commit, because it never checks that the commit's `stack`/`repository` corresponds to the payload's `repository` field that was used for authentication.

### Impact Explanation
`Commit#deployable?` and continuous delivery scheduling depend directly on commit status state (`success? && !blocked?`) via `add_status`/`schedule_continuous_delivery`. [7](#0-6) [8](#0-7)  By forging a `success` status for a commit belonging to a stack the attacker has no legitimate access to (a different org's repository), an attacker can flip that commit into a deployable state and trigger continuous deployment, i.e., an unauthorized deploy — this matches the Critical-tier impact ("cross-repository writes" / "an unauthorized deploy").

### Likelihood Explanation
Exploitability is conditioned on the target Shipit instance running the documented multi-organization configuration with at least one organization configured without a `webhook_secret` — a state the project's own setup documentation presents as a normal, supported option rather than a misconfiguration. Given that condition, no session, `ApiClient` token, or GitHub credentials of any kind are required; only knowledge of a target commit's `sha` (visible in Shipit's own UI/API) is needed.

### Recommendation
Bind webhook authentication to the specific `repository.full_name` (not just `owner.login`), and require handlers such as `StatusHandler` and `CheckSuiteHandler` to scope lookups (`Commit.where(sha: ...)`, stack resolution) to the repository that was actually verified in `verify_signature`, rather than trusting `payload['repository']['full_name']` independently downstream. Additionally, consider making `webhook_secret` mandatory (reject requests when absent) rather than silently authenticating everyone when it is unset.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `orgA` (has `webhook_secret` set, tracks `orgA/secret-repo`, commit `deadbeef` pending CI) and `orgB` (no `webhook_secret` configured).
2. Attacker (no credentials) sends:
```
POST /webhooks
X-Github-Event: status
{
  "sha": "deadbeef",
  "state": "success",
  "repository": { "owner": { "login": "orgB" }, "full_name": "orgB/whatever" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "orgB")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally. [4](#0-3) 
4. `StatusHandler#process` executes `Commit.where(sha: "deadbeef")`, matches the commit under `orgA/secret-repo`, and calls `create_status_from_github!`, marking it successful — despite the request never being authenticated against `orgA`'s secret. [1](#0-0) 
5. If continuous deployment is enabled on that stack, the forged success status can trigger an unauthorized deploy.

### Citations

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

**File:** docs/setup.md (L20-30)
```markdown
## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
