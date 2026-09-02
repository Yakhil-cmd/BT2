### Title
Cross-organization status forgery via unbound `repository.owner.login` vs global `sha` lookup - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against using `repository.owner.login` from the *unverified* JSON body, but `StatusHandler#process` (and other handlers) act on a field — the commit `sha` — that is never bound to that organization. Because `Commit.where(sha: params.sha)` is a *global*, unscoped lookup across every stack/repository in the Shipit instance, any organization whose webhook is reachable (in particular one configured with `webhook_secret: nil`, a supported and documented configuration) can be used to forge a `status` webhook that writes a fabricated commit status onto a commit belonging to a completely different, unrelated, and properly-secured repository/organization.

### Finding Description
`Shipit.github(organization: repository_owner)` picks the GitHub App config to verify against, where `repository_owner` is read straight from the untrusted payload: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected organization has no `webhook_secret` configured: [3](#0-2) 

This is a documented, first-class configuration option (`webhook_secret: # nil`) shown in the shipped config templates: [4](#0-3) [5](#0-4) 

Once the request passes `verify_signature`, `WebhooksController#create` dispatches the entire (attacker-controlled) JSON body to every registered handler for the event, with no re-check that the `repository`/`organization` used for signature selection matches the `repository`/`sha` the handler actually operates on: [6](#0-5) 

Most handlers scope their side effects to a specific repository via `Repository.from_github_repo_name(repository.full_name)`: [7](#0-6) 

But `StatusHandler` does not use this repository scoping at all — it looks up commits **globally by `sha`**, across every stack in the whole Shipit instance, and writes an attacker-supplied `state`/`description`/`target_url`/`context` onto them: [8](#0-7) 

This breaks the binding: **organization authenticated (`repository.owner.login`, used to select the webhook secret) ≠ commit/repository actually written (`sha`, matched globally with no ownership check)**. An attacker who controls (or targets) any organization entry in `Shipit`'s config with `webhook_secret: nil` — or who otherwise obtains a valid signature for *any* configured organization — can submit a `status` event whose `sha` collides with a commit that belongs to an entirely different, unrelated, properly-secured repository/organization, and have Shipit accept it as a legitimate CI status for that commit.

### Impact Explanation
A forged commit status directly feeds `Commit#deployable?` (`success? && !blocked?`) and the merge/continuous-delivery pipeline: [9](#0-8) [10](#0-9) 

Marking a commit as `success` via a forged status can satisfy `ci.require`/`required_statuses` checks and unblock continuous delivery (`ContinuousDeliveryJob`) or a manual deploy for a stack/organization the attacker never authenticated against — i.e. an unauthorized deploy triggered by data written to the wrong organization's commit history. This matches the Critical "unauthorized deploy" impact class: the write is a cross-repository/cross-organization write of trust-relevant data (CI status) enabled purely because the signature-selecting field (`repository.owner.login`) and the data-mutating field (`sha`, unscoped) are never checked against each other.

### Likelihood Explanation
Likelihood is high wherever any organization entry in the Shipit deployment has `webhook_secret` unset — an explicitly supported and templated configuration in this repo's own config samples — or wherever an attacker can otherwise produce one valid signature for any org (e.g. via a compromised/low-trust GitHub App). No repository write access, GitHub App private key, or Shipit session/API token is required; only the ability to send an HTTP request to the public `/webhooks` endpoint with a crafted JSON body and (if required) a signature computed from a leaked/absent secret for *any one* configured organization. Colliding `sha` values across independent repositories are also plausible in practice (shared history, cherry-picks, forks, or simply brute-forcing short-lived SHAs of low-security stacks) increasing exploitability further.

### Recommendation
- In `StatusHandler#process`, scope the `Commit` lookup to the repository derived from the verified payload (via `stacks`/`repository_name`, as other handlers already do) instead of querying `Commit.where(sha:)` globally.
- In `WebhooksController#verify_signature`, cross-check that the organization used to select the webhook secret actually owns the `repository.full_name` referenced later in the payload before dispatching to handlers.
- Treat organizations configured with `webhook_secret: nil` as a documented risk and consider rejecting/segregating webhook processing for such orgs from acting on data belonging to other, secured organizations.

### Proof of Concept
1. Configure (or find) an organization `OrgLowTrust` in `Shipit.secrets.github` with `webhook_secret: nil` (a supported configuration per `config/secrets.development.shopify.yml`).
2. Identify a target commit `sha` belonging to a Stack under a different, secured organization `OrgSecure` (e.g. from public commit history).
3. POST to `/webhooks` with header `X-Github-Event: status` and a signature header of any value (verification is skipped because `webhook_secret` is `nil` for the org derived from `repository.owner.login`), and a body:
```json
{
  "sha": "<target sha owned by OrgSecure/some-repo>",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "OrgLowTrust" }, "full_name": "OrgLowTrust/throwaway-repo" }
}
```
4. `verify_signature` selects `Shipit.github(organization: "OrgLowTrust")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the commit under `OrgSecure`, writing a fabricated `success` status via `create_status_from_github!`, potentially unblocking deploy/merge for `OrgSecure`'s stack despite the attacker never authenticating against `OrgSecure`.

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

**File:** config/secrets.development.shopify.yml (L6-18)
```yaml
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
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
