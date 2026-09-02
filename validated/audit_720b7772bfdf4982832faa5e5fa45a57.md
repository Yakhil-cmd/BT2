### Title
Webhook signature is verified against the org derived from `repository.owner.login`, but every webhook handler routes and acts on the repository from the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` picks *which* GitHub App/organization secret to validate the HMAC signature against using `repository.owner.login` (or `organization.login`), but every downstream `Shipit::Webhooks::Handlers::Handler` subclass decides *which repository/stack to act on* using the independent `repository.full_name` field of the very same JSON body. Since nothing binds these two fields together, a party that legitimately controls one configured GitHub organization's webhook secret in a multi-org Shipit deployment can forge a payload where the two fields point at different repositories, letting them push actions (sync, PR-triggered review-stack provisioning, archiving, etc.) against a victim organization's repository while only proving possession of their own org's secret.

### Finding Description
The signature check resolves the app/secret to verify with like this: [1](#0-0) [2](#0-1) 

`repository_owner` is taken from `params.dig('repository', 'owner', 'login')`, and that value selects the `Shipit.github(organization: repository_owner)` app instance whose `webhook_secret` is used in `verify_webhook_signature`: [3](#0-2) 

Once the signature check passes, `create` hands the **entire raw parsed body** (not just the "authenticated" repository field) to the event handlers: [4](#0-3) 

Every handler resolves the target repository/stack from a *different* field, `repository.full_name`, with no cross-check against the field used for signature-org resolution: [5](#0-4) 

This pattern repeats across all handlers, e.g. `PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`, which all resolve `repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`: [6](#0-5) [7](#0-6) 

The binding broken is: `organization authenticated by verify_signature` (`repository.owner.login`) `≠` `repository the handler writes to` (`repository.full_name`). In a Shipit instance configured with multiple organizations (a documented, supported configuration — see `config/secrets.development.shopify.yml` and `docs/setup.md`), each org has its own `webhook_secret` that the org's own administrators legitimately know (they set it when creating their GitHub App). Nothing stops one org's payload from carrying a `repository.full_name` belonging to a different, already-onboarded repository/org in the same Shipit instance.

### Impact Explanation
An attacker who administers **any one** configured GitHub organization/App on a shared, multi-org Shipit instance can sign a crafted webhook payload with their own known `webhook_secret`, set `repository.owner.login` to their own org (so `verify_signature` passes) and set `repository.full_name` to a victim organization's already-onboarded repository. The request is accepted and routed to handlers that will act on the victim's stacks:
- `PushHandler` triggers `stack.sync_github(expected_head_sha: ...)` on the victim's stacks.
- `PullRequest::OpenedHandler` → `ReviewStackAdapter#find_or_create!` creates a review stack for the victim repository using attacker-controlled `pull_request.head.ref` (branch) and queues it for provisioning (`ReviewStackProvisioningQueue.add`), which can result in an actual deploy/provisioning task being enqueued against the victim's infrastructure/branch of the attacker's choosing.
- `ClosedHandler`/`LabeledHandler`/`UnlabeledHandler`/`ReopenedHandler` archive/unarchive victim review stacks.

This is a cross-repository write / unauthorized-deploy-trigger primitive that crosses a tenant boundary using only the attacker's own legitimately-held credentials, matching the "Critical - cross-repository writes, unauthorized deploy" impact bucket.

### Likelihood Explanation
Requires that the Shipit deployment be configured for multiple GitHub organizations (a supported, documented configuration) and that the attacker administers one of them, plus that the targeted victim repository is already onboarded as a `Shipit::Repository`/`Stack` in the same instance. No privileged Shipit account, session, or API token is required — only knowledge of the attacker's own org's webhook secret, which they legitimately possess. Likelihood is moderate: it depends on multi-tenant deployment, but where present the exploit path requires no additional social engineering.

### Recommendation
After signature verification, re-derive the acting repository from the same field used to select the signing organization (or verify that `repository.full_name`'s owner matches `repository.owner.login`/`organization.login`), and reject the webhook if they diverge. Alternatively, have `verify_signature` attempt validation against every configured organization's secret rather than trusting an attacker-supplied field to select which secret to check, or pin one Shipit instance to one organization's secret exclusively when multi-org config is not required.

### Proof of Concept
1. Shipit is configured with two orgs, `attacker-org` (secret `S_A`) and `victim-org` (secret unknown to attacker), each with onboarded repositories.
2. Attacker crafts a `pull_request` (`opened`) webhook JSON body with:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
   - `pull_request.head.ref = "attacker-branch"`
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, body)` using their own known secret.
4. POST to `/webhooks` with `X-Github-Event: pull_request`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, verifies with `S_A` → passes.
6. `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler` resolves `repository` via `params.repository.full_name` = `"victim-org/victim-repo"`, and (if review-stack provisioning is enabled for that repo) creates/provisions a review stack on branch `attacker-branch` for the victim repository — an action performed on `victim-org`'s repository despite the request having only been signed with `attacker-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-66)
```ruby
          def repo_name
            params.repository["full_name"]
          end
```
