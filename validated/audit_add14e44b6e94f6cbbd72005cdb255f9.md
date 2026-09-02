## Title
Cross-Organization Commit Status Forgery via Unbound `repository.owner.login` vs `repository.full_name` in Webhook Signature Verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate a request against using `repository_owner`, taken from the payload's `repository.owner.login` (or `organization.login`) field. However, once the signature check passes, downstream event handlers (e.g. `StatusHandler`) act on a *different*, independently-controlled field of the same JSON body — `repository.full_name` — or, in the case of `StatusHandler`, on no repository-scoping field at all. Because the signature only proves "the sender knows the secret configured for whatever `repository.owner.login` claims," and Shipit supports multiple independently-configured GitHub organizations sharing a single `/webhooks` endpoint, a party holding one organization's webhook secret can forge a payload whose "authenticating" field points to their own org while the "acted upon" data (commit SHA, statuses) targets a stack belonging to a different organization/repository.

### Finding Description
`Shipit::Engine` mounts a single public endpoint, `resources :webhooks, only: :create`, for all configured GitHub organizations [1](#0-0) . Shipit explicitly supports hosting multiple, unrelated GitHub organizations on one instance, each with its own `webhook_secret`, as documented in `docs/setup.md` and shown in the multi-org config fixture `test/dummy/config/secrets_double_github_app.yml` [2](#0-1) .

`WebhooksController#verify_signature` picks the GitHub App (and therefore the secret) to check against using a field extracted from the untrusted JSON body itself:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

The HMAC signature only proves the sender knows the secret bound to whatever `repository.owner.login` value is present — it does **not** prove that the rest of the payload (in particular `repository.full_name`, or a bare commit `sha`) actually belongs to that organization. Since anyone can `POST /webhooks` directly (GitHub delivery is not required — it's a normal internet-reachable Rails route), an attacker who legitimately controls the webhook secret for **their own** organization ("OrgA", installed on the same shared Shipit instance) can:
1. Set `repository.owner.login` (or `organization.login`) to `"OrgA"` so `verify_signature` passes using OrgA's secret.
2. Set the event-specific fields to target **any other** organization's stack.

`StatusHandler`, which handles the `status` webhook event, is the sharpest instance of this because it doesn't scope by repository at all — it matches purely on commit SHA across the entire installation:

```ruby
class StatusHandler < Handler
  params do
    requires :sha, String
    requires :state, String
    accepts :description, String
    accepts :target_url, String
    accepts :context, String
    accepts :created_at, String
    accepts :branches, Array do
      requires :name, String
    end
  end

  def process
    Commit.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
``` [4](#0-3) 

`Commit.where(sha: params.sha)` is a global, cross-stack, cross-repository, cross-organization lookup — it is not filtered by `repository.owner.login`/`repository.full_name` at all. This means the org bound by the signature (OrgA) has zero relation to the commit(s) whose CI status gets overwritten. Once a matching commit is found, `create_status_from_github!(params)` persists attacker-supplied `state`, `description`, `target_url`, and `context` directly as a real `CommitStatus`/`Status` record, with no re-verification against GitHub's API.

Other handlers derive repo scope via `Handler#repository_name` (`payload.dig('repository', 'full_name')`) [5](#0-4) , which is likewise never cross-checked against the `repository.owner.login`/`organization.login` value used for signature selection — an attacker authenticated as OrgA can set `full_name` to `"OrgB/some-repo"` and still pass the check, since GitHub's real webhook delivery (which would enforce this consistency) is bypassed entirely by POSTing straight to the endpoint.

This is the multi-tenant analog of the reported bug class: the field verified by the cryptographic check (`repository.owner.login`, which selects the signing secret) is not the same field that downstream code trusts to select what gets written (`repository.full_name` / bare commit `sha`), breaking the equality `authenticated_organization == acted_upon_repository`.

### Impact Explanation
An attacker who is a legitimate integrator/admin for one GitHub organization hosted on a shared multi-tenant Shipit instance can forge commit statuses for commits belonging to a completely different, unrelated organization's stacks. Forged "success" statuses on required/blocking CI contexts (`ci.require`, `ci.blocking`, `merge.require`) directly influence `Commit#deployable?` [6](#0-5)  and `MergeRequest#all_status_checks_passed?` gating logic [7](#0-6) , which gate both manual deploys and the automated merge queue (`ProcessMergeRequestsJob` merges PRs once `all_status_checks_passed?` is true) [8](#0-7) . This can result in an unauthorized deploy or an unauthorized merge for a victim organization's repository — squarely Critical impact per the defined scope ("an unauthorized deploy, rollback, or merge").

### Likelihood Explanation
Requires the attacker to control a legitimate webhook secret for at least one organization hosted on a shared/multi-tenant Shipit deployment (a configuration explicitly documented and supported: `docs/setup.md`, "Using Multiple Github Applications"). No GitHub-side compromise of the victim organization is required — the attacker never needs write access to the victim's repository or org, only knowledge of any one organization's own configured secret plus the ability to POST directly to the shared `/webhooks` endpoint, which is by design internet-reachable and unauthenticated aside from the HMAC check.

### Recommendation
Bind the field used to select the verifying secret to the field(s) used by handlers to select the target resource, and validate they are internally consistent before dispatching to handlers:
- In `WebhooksController`, after determining `repository_owner`, also parse `repository.full_name` and require that its owner segment matches `repository_owner` (case-insensitively) before continuing.
- In `Handlers::Handler`/`StatusHandler`, scope `Commit` lookups (and any other cross-cutting lookups) by the repository actually authenticated for the request, not merely by an unscoped attribute like `sha`. Pass the verified organization/repository context from the controller into the handler and require handlers to filter through it.
- Consider signing with a repo/org-specific secret verified against the value used for resource resolution, so a single compromised or attacker-owned secret cannot be replayed against unrelated tenants' data.

### Proof of Concept
Given a shared Shipit instance configured with two organizations, `OrgA` (attacker-controlled) and `OrgB` (victim), and knowing `OrgA`'s `webhook_secret`:

1. Identify a real commit SHA belonging to a `OrgB` stack that Shipit tracks (e.g. observable from a stack's public commit history page, or brute-forced/guessed if reused).
2. Craft a `status` event payload:
```json
{
  "sha": "<OrgB's commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged",
  "repository": { "owner": { "login": "OrgA" } }
}
```
3. Compute `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)`.
4. `POST /webhooks` with header `X-Github-Event: status` and the above body/signature directly to the Shipit instance.
5. `verify_signature` resolves `repository_owner` → `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully because it was computed with OrgA's real secret over this exact body [9](#0-8) .
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the `OrgB` commit — and calls `commit.create_status_from_github!(params)`, writing a forged "success" status onto `OrgB`'s commit [10](#0-9) .
7. If that context is in `OrgB`'s `ci.require`/`merge.require` list, the forged status can unblock a deploy or trigger an automatic merge on `OrgB`'s stack that OrgA has no legitimate authorization over.

### Citations

**File:** config/routes.rb (L14-14)
```ruby
  resources :webhooks, only: :create
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-6)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-39)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-27)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
```
