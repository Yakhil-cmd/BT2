Confirmed: `Commit#create_status_from_github!` via `StatusHandler` directly creates a `Status` record that affects `Commit#deployable?` (`success? && !blocked?`), which gates `Stack#next_expected_commit_to_deploy` and `ContinuousDeliveryJob`. This is sufficient to establish real deploy-gating impact from forged statuses.### Title
Webhook signature verification keys off `repository.owner.login` while all handlers act on `repository.full_name`, allowing forged cross-repository events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) in the payload, but every `Webhooks::Handlers::Handler` subclass resolves the target `Repository`/`Stack` to act on using a *different* field, `repository.full_name`, taken from the same attacker-controlled JSON body. Because the two fields are never checked for consistency, an operator/admin of one GitHub organization configured in Shipit (who legitimately knows their own org's `webhook_secret`) can send a payload whose signature validates against their own org while `repository.full_name` points at a completely different repository/stack tracked by Shipit, letting them trigger handler side effects (fake CI statuses, syncs, PR-driven stack archival/provisioning) against a repository they do not own.

### Finding Description
`verify_signature` derives the signing organization solely from `repository.owner.login`/`organization.login` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` against the *raw* request body: [1](#0-0) [2](#0-1) 

The signature check itself is a straightforward HMAC-SHA1 over the whole payload using that organization's `webhook_secret`: [3](#0-2) 

Once verification passes, the base `Handler` class (used by `PushHandler`, `StatusHandler`, all `PullRequest::*Handler`s, etc.) resolves the acted-upon repository/stack via a *different* payload field, `repository.full_name`, with no cross-check against `repository.owner.login`: [4](#0-3) 

Since Shipit supports multiple GitHub organizations each with its own `webhook_secret` (documented "Using Multiple Github Applications" setup), an attacker who administers *any* one of these configured GitHub orgs knows that org's `webhook_secret` and can compute a valid signature for an arbitrary JSON body of their choosing. They simply set `repository.owner.login` to their own org (so verification succeeds using the secret they know) while setting `repository.full_name` to `"victim-org/victim-repo"` (a repository tracked under a different org's Shipit configuration). The signature is valid for the literal bytes sent, so mismatching the two `repository` sub-fields does not break verification.

Downstream, `StatusHandler#process` looks up `Commit.where(sha: params.sha)` scoped globally (not restricted to the verified organization) and calls `commit.create_status_from_github!`, which creates a `Status` row that directly feeds `Commit#deployable?` (`success? && !blocked?`) and `Stack#next_expected_commit_to_deploy`/`ContinuousDeliveryJob`: [5](#0-4) [6](#0-5) 

Similarly `PushHandler#process` and the `PullRequest::*Handler`s resolve stacks purely via `repository.full_name` and trigger `stack.sync_github`, archive/unarchive review stacks, or create review-stack provisioning, all cross-organization: [7](#0-6) [8](#0-7) 

This is the same class of bug as the reported Solidity finding: a value that is checked/verified (the organization tied to the signature) is not the same value that is subsequently trusted to authorize the state-changing action (the repository the handler writes to). The binding `organization_verified == repository_acted_on` is broken.

### Impact Explanation
By forging a `status` webhook for a commit SHA belonging to a repository/stack outside the attacker's own organization, an attacker can inject a fabricated `success` CI status that satisfies `Commit#deployable?`, enabling an unauthorized deploy to proceed on a stack the attacker has no legitimate access to (via continuous deployment or by satisfying the "deployable" gate that human operators rely on before manually triggering a deploy). This is a cross-repository write / unauthorized-deploy-enabling primitive, matching the report's "Critical: unauthorized deploy" impact tier. Lower-severity variants of the same root cause also let the attacker archive/unarchive review stacks or force a `GithubSyncJob` for a repository they don't own.

### Likelihood Explanation
Exploitation requires the attacker to control (as an admin) at least one GitHub organization that is configured as one of Shipit's `github` entries in `config/secrets.yml` (i.e., they legitimately know that org's `webhook_secret`, obtained during normal GitHub App/webhook setup for their own org) and knowledge that Shipit tracks a target repository under a different org. No `ApiClient` token, no GitHub write access to the victim repo, and no Shipit account is required — only the ability to POST to the shared `/webhooks` endpoint with a self-signed payload. This is realistic in any deployment using the documented multi-organization configuration, but not exploitable in single-organization deployments since there the attacker would already need the sole `webhook_secret` (a privileged secret) to forge anything, and the "victim" repos are all under the same org, so the binding violation becomes moot in that narrower case.

### Recommendation
- Short term: In `WebhooksController#verify_signature`/`Handlers::Handler`, require that the organization used to select the `webhook_secret` (`repository.owner.login`) matches the organization portion of `repository.full_name` used by the handler, and reject the webhook (422) if they differ.
- Long term: Have `Handler#stacks`/`#repository_name` receive the already-verified organization from the controller and scope repository lookups (`Repository.from_github_repo_name`) to that organization, rather than trusting an unauthenticated field of the payload independently of the signature-checked one. Add regression tests asserting that a payload with mismatched `repository.owner.login` and `repository.full_name` organizations is rejected.

### Proof of Concept
1. Shipit is configured with two GitHub orgs in `config/secrets.yml`: `attacker-org` (with `webhook_secret: S1`, installed/administered by the attacker) and `victim-org` (tracking `victim-org/victim-repo`, unrelated to the attacker).
2. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "<known sha of a commit in victim-org/victim-repo>",
  "state": "success",
  "context": "ci/travis",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S1, raw_body)` using their own known `webhook_secret`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"` and calls `Shipit.github(organization: "attacker-org").verify_webhook_signature(signature, raw_body)`, which succeeds because the attacker signed with the correct secret for that org.
5. `StatusHandler#process` runs unaffected by the org mismatch, finds the commit by `sha` in the `victim-org/victim-repo` stack, and calls `create_status_from_github!`, marking it `success`.
6. If continuous deployment or manual deploy is gated only on `Commit#deployable?`, the victim stack now considers that commit deployable, despite no legitimate CI signal or GitHub credential for `victim-org` ever being presented.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
