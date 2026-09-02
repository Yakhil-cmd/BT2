### Title
Unauthenticated forgery of GitHub `status`/`push` webhooks when an organization's `webhook_secret` is unset drives an unauthorized continuous-delivery deploy - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` binds trust in an inbound webhook to `Shipit.github(organization: repository_owner).verify_webhook_signature`, but `GithubApp#verify_webhook_signature` treats an unset `webhook_secret` as automatic success. Since Shipit's own setup docs describe the GitHub App webhook secret as *optional*, an organization can be legitimately configured without one, and the "authenticated organization" side of the binding becomes vacuous — any unauthenticated caller can then POST a `status` event straight to `/webhooks`, and Shipit will treat it exactly like a real GitHub signal, up to and including triggering an unattended, unauthorized deploy via continuous delivery.

### Finding Description
The binding this endpoint is supposed to enforce is: *"the organization whose secret validated this payload" == "the organization on whose behalf we are about to mutate state."* The check is: [1](#0-0) [1](#0-0) 

and the underlying verifier is: [2](#0-1) 

`return true unless webhook_secret` means that for any organization configured without a `webhook_secret` — which the project's own docs present as optional — `verify_signature` passes unconditionally, regardless of the `X-Hub-Signature` header or its absence: [3](#0-2) 

Once past this check, the controller dispatches the raw, attacker-controlled JSON body straight to the registered handlers: [4](#0-3) 

The `status` handler looks up commits purely by SHA (no ownership check tying the SHA back to the "authenticated" organization) and writes a GitHub-status record from the attacker-supplied `state`: [5](#0-4) 

`Commit#create_status_from_github!` feeds directly into `Commit#deployable?` and `Commit#schedule_continuous_delivery`, which enqueues an automatic deploy job with no human or credential involved: [6](#0-5) [7](#0-6) 

So the equality the system is supposed to preserve — *organization that authenticated the webhook == organization whose commit/stack state is being written* — degenerates to *no authentication at all* whenever an org omits the optional webhook secret, letting anyone forge a "CI success" signal for any commit belonging to that org's stacks.

### Impact Explanation
This reaches the required Critical bar of "an unauthorized deploy": for a stack with `continuous_deployment: true` and no `ci.require`/CI gating beyond generic status checks, an attacker can forge a `status` webhook with `state: success` for the head commit of a branch, which flips `Commit#deployable?` to true and causes `schedule_continuous_delivery` to enqueue `ContinuousDeliveryJob`, deploying attacker-chosen code with zero Shipit credentials, GitHub App private key, or webhook secret needed — only knowledge that the target org has left the (documented-as-optional) webhook secret blank.

### Likelihood Explanation
Likelihood depends entirely on operational configuration: any Shipit deployment where at least one onboarded GitHub organization was set up without a webhook secret (explicitly permitted by `docs/setup.md`) is fully exposed, with no additional barrier — the `/webhooks` route is public and unauthenticated by design. Since the field is marked optional and no runtime warning or hard requirement exists elsewhere in the code, this is a realistic and easy-to-overlook misconfiguration, not a purely theoretical one.

### Recommendation
Require a non-blank `webhook_secret` per configured GitHub organization at boot/config-validation time (or make `Shipit.github(...)` refuse to construct an app without one), and make `verify_webhook_signature` fail closed (return `false`, not `true`) whenever `webhook_secret` is blank. Additionally, tie handler-side lookups (`repository.full_name`, commit SHA) back to the same organization that was authenticated in `verify_signature`, so a webhook validated for org A cannot be used to mutate stacks belonging to org B even when secrets are present.

### Proof of Concept
1. Configure (or identify) a Shipit-tracked GitHub organization `victim-org` whose `config/secrets.yml` entry has `webhook_secret` blank/nil (a supported, documented configuration).
2. As an unauthenticated attacker, POST directly to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<head-sha-of-a-continuous-deployment-stack>",
  "state": "success",
  "context": "ci",
  "repository": { "owner": { "login": "victim-org" } }
}
```
No `X-Hub-Signature` header is required — `verify_webhook_signature` short-circuits to `true`.
3. `StatusHandler#process` creates a success status on the targeted commit; if the stack has `continuous_deployment: true`, `Commit#schedule_continuous_delivery` enqueues `ContinuousDeliveryJob`, and the attacker-targeted commit is deployed without any Shipit login, `ApiClient` token, or GitHub credential.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
