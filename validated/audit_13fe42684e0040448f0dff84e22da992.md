Confirmed: `WebhooksController#verify_signature` derives the signing organization from `repository.owner.login` (or `organization.login`) in the untrusted JSON body, and looks up the per-organization `webhook_secret` via `Shipit.github(organization: repository_owner)`. That secret is then used only to HMAC-validate the raw request body as a whole. The individual handlers that subsequently act on the payload (`PushHandler`, `LabelCapturingHandler`, `ClosedHandler`, etc.) locate the target `Stack`/`Repository` using a *different* field of the same body: `repository.full_name`, via `Repository.from_github_repo_name(params.repository.full_name)`.

### Title
Webhook signature verified against `repository.owner.login`'s secret while handlers act on the independent, unvalidated `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The bug class from the external report is a TOCTOU/binding break: a value is checked/authorized against one piece of state while a *different* piece of state is what actually gets acted upon. In shipit-engine, `WebhooksController#verify_signature` selects the HMAC secret using `repository.owner.login` (falling back to `organization.login`), but the downstream `Shipit::Webhooks::Handlers::Handler` base class and all its subclasses resolve the affected stack using the sibling, independently-controlled JSON field `repository.full_name`. Since these two fields live in the same attacker-supplied JSON body and are never cross-checked against each other, an attacker who controls one GitHub organization/repository configured on the Shipit instance (with a known/derivable webhook secret for that org) can forge a signature that is valid for their own org while setting `repository.full_name` to a victim's repository, causing Shipit to process the "authenticated" webhook against the wrong stack.

### Finding Description
`verify_signature` computes the signing key from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` resolves a `GitHubApp`/`GithubHook` configuration scoped to that organization, and `verify_webhook_signature` HMACs the raw body with that organization's `webhook_secret`: [3](#0-2) 

Once the signature check passes, every webhook handler ignores `repository.owner.login` entirely and instead resolves the target repository/stack via `repository.full_name`: [4](#0-3) [5](#0-4) [6](#0-5) 

Nothing in the controller or in `Shipit::Webhooks::Handlers::Handler` enforces that `repository.full_name` actually belongs to the organization identified by `repository.owner.login`/`organization.login`. The signature only proves "this body was signed with organization X's secret" — it says nothing about which repository the body's other fields describe. Before/after the attack:
- Before: signature validity is meant to imply "this event genuinely originates from GitHub for org/repo `full_name`."
- After: an attacker with one legitimate/known GitHub App installation (and its `webhook_secret`) on org A can submit a signed body where `repository.owner.login = "org-A"` (so the signature check passes) but `repository.full_name = "org-B/victim-repo"`, so `PushHandler`, label/close/reopen handlers, membership, or check-run handlers operate on org B's stacks.

### Impact Explanation
This breaks the binding "organization authenticated versus repository written." Depending on the handler triggered, an attacker could: trigger `stack.sync_github` for a victim stack/branch (`PushHandler`), archive/unarchive review stacks (`LabeledHandler`, `ClosedHandler`, `ReopenedHandler`), or forge commit statuses/check runs feeding into merge-queue and deploy decisions for a repository the attacker does not control — all without ever needing GitHub write access to the victim repository, an `ApiClient` token, or a Shipit session. This can influence unauthorized deploys/merges (e.g., forging a passing status/check-run that a merge queue or continuous-delivery check relies on), which lands in the Critical/High impact bucket ("cross-repository writes" / "unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitability requires the attacker to have at least one organization/repository legitimately configured with the Shipit instance (i.e., a `webhook_secret` they can obtain, e.g., by being an admin of one org onboarded to a shared Shipit deployment) — this is a materially lower bar than requiring write access to the victim's specific repository, an API token, or a Shipit session, and is exactly the class of "unprivileged attacker crossing an authentication boundary" this scan targets. Whether a real deployment configures distinct webhook secrets per organization (multi-tenant) determines the severity in practice, but the code contains no cross-field validation regardless.

### Recommendation
After verifying the signature, validate that `repository.full_name`'s owner matches the `repository_owner`/`organization.login` used to select the secret (or, more robustly, verify the signature using a single shared secret and independently confirm the resolved `Repository`'s `owner` matches the org whose installation delivered the event, e.g. via the `X-GitHub-Hook-Installation-Target-ID` header rather than payload-derived fields).

### Proof of Concept
1. Shipit is configured with GitHub Apps for `org-attacker` and `org-victim`, each with its own `webhook_secret` (multi-tenant install), and `org-victim/some-repo` has a Shipit stack with `merge_queue_enabled: true`.
2. Attacker crafts a `status` (or `push`) webhook JSON body with `repository.owner.login = "org-attacker"` but `repository.full_name = "org-victim/some-repo"` and a `sha` matching a pending PR head commit in the victim stack.
3. Attacker computes `X-Hub-Signature` using `org-attacker`'s known `webhook_secret` over the raw body and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner = "org-attacker"`, fetches `org-attacker`'s secret, and the HMAC check passes.
5. `Shipit::Webhooks.for_event('status')` handler resolves the target commit/stack via `repository.full_name = "org-victim/some-repo"`, creating a forged success status on `org-victim`'s commit, which can unblock its merge queue/deploy despite the attacker having no access to `org-victim`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
          end
```
