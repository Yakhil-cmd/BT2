## Title
Webhook signature is verified against the organization named in the payload, but stack/repository selection trusts a different, unrelated payload field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The reported CCMP bug is a class of *"trust binding broken by an unvalidated field"*: a privileged action (ownership/executor transfer) is taken based on a value that is never checked against what the caller is actually authorized to set. The same class of bug exists in Shipit's webhook ingestion path: the **organization used to select and verify the HMAC signature** and the **repository that ends up being mutated** are two independent fields of the same attacker-controlled JSON body, and nothing ties them together.

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App/secret to check the signature against using a field read straight out of the still-unverified JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` returns `params.dig('repository', 'owner', 'login')`. `Shipit.github(organization: repository_owner)` returns the `GithubApp` configured for *that* organization, and its `webhook_secret` is used to validate `X-Hub-Signature`: [3](#0-2) 

If the signature matches the secret of the organization named in `repository.owner.login`, the whole payload is accepted and dispatched to handlers. However, every downstream handler determines *which repository/stack to act on* from a **different** field, `repository.full_name`, without re-checking that its owner segment matches `repository.owner.login`: [4](#0-3) [5](#0-4) 

Because both `repository.owner.login` and `repository.full_name` live inside the same freely-writable JSON body, an attacker who legitimately administers **their own** GitHub organization/App (and therefore legitimately knows *their own* `webhook_secret`, configured for their org in `config/secrets.yml`) can craft a payload where:
- `repository.owner.login = "attacker-org"` (so the HMAC is verified against attacker-org's own, correctly known secret), while
- `repository.full_name = "victim-org/victim-repo"` (so `Repository.from_github_repo_name` / `Handler#stacks` resolves to a stack belonging to a completely different tenant of the same Shipit instance).

The equality that should hold but doesn't is:
`organization authenticated by verify_signature (repository.owner.login)` == `repository actually written by the handler (repository.full_name)`.

Before the attack: the attacker can only affect their own org's webhook processing. After: by simply changing `full_name` in a JSON body they otherwise legitimately sign, they can inject events (push, pull_request opened/edited/assigned, status, check_suite, membership) that are processed as if they came from any other repository/stack tracked by the same Shipit deployment — because signature validity says nothing about which repository the payload is allowed to describe.

### Impact Explanation
Depending on which handler is hit, this cross-tenant confusion can:
- Fabricate `push` events for a victim stack, which `Handler#stacks`/`GithubSyncJob` will process, potentially advancing `undeployed_commits_count`, mutating cached commit state, or (where `continuous_deployment` is enabled) contributing to triggering an unauthorized deploy of the victim stack.
- Spoof `pull_request opened` events causing unauthorized creation of review stacks for a repository the attacker doesn't control (`ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`).
- Spoof `status`/`check_suite` events, corrupting commit status data relied on for merge-queue and continuous-deployment decisions on a repo the attacker does not own.

This crosses a repository trust boundary (an org's credential being used to mutate a different org's data), matching the "cross-repository writes / unauthorized deploy" impact tier.

### Likelihood Explanation
Likelihood is limited because the attacker still needs to be an onboarded org with a valid `webhook_secret` configured in the Shipit instance (i.e., someone who can legitimately install the Shipit GitHub App on at least one organization tracked by this instance) — this mirrors the low likelihood scored in the original report (only the "owner" can call the vulnerable function; here, only an already-onboarded org can sign a webhook at all). It does **not** require compromising the victim's secret, an `ApiClient` token, a Shipit session, or repository write access on GitHub, so it remains an unprivileged-attacker path relative to the victim tenant.

### Recommendation
After signature verification succeeds, re-derive the organization strictly from the verified GitHub App context and assert that `repository.full_name`'s owner segment (and/or `organization.login` payload field) matches the organization whose secret validated the signature, rejecting the webhook (422) on mismatch, before any handler resolves stacks/repositories from `repository.full_name`.

### Proof of Concept
1. Attacker legitimately installs Shipit's GitHub App on `attacker-org` and knows `attacker-org`'s `webhook_secret` (as documented in `docs/setup.md`).
2. Attacker POSTs to `/webhooks` with `X-Github-Event: pull_request`, a body where `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"`, `action = "opened"`, and a valid `X-Hub-Signature` computed with `attacker-org`'s secret.
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against `attacker-org`'s secret.
4. `PullRequest::OpenedHandler#repository` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and, if review stacks are enabled/permitted, provisions a review stack for `victim-org/victim-repo` on behalf of the attacker, despite the attacker never having proven any relationship with `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
