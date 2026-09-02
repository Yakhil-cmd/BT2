### Title
Webhook signature verified against `repository.owner.login` but repository/stack targeted via unbound `repository.full_name` — cross-organization forgery of commit statuses - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the same "unbacked deposit" bug class: a value that drives a privileged state change (`DepositState`) is never validated against the artifact that is actually verified/transferred (the token transfer). In Shipit, the `WebhooksController` verifies the HMAC signature of an inbound webhook against the GitHub organization named in the payload (`repository.owner.login`), but the code path that actually acts on the payload (`Shipit::Webhooks::Handlers::Handler#repository_name`) resolves the target `Repository`/`Stack` from a *different, independently attacker-controlled* field of the same JSON body: `repository.full_name`. Nothing binds these two fields together, so a valid signature for organization A does not guarantee that the payload's target repository actually belongs to organization A.

### Finding Description
`WebhooksController#verify_signature` selects which secret to check the HMAC against using only the organization name embedded in the untrusted request body: [1](#0-0) [2](#0-1) 

Each configured GitHub organization has its own `webhook_secret` in Shipit's multi-tenant configuration: [3](#0-2) 

Once the signature is accepted, the event handler resolves the actual `Repository`/`Stack` to mutate using a *separate* field of the same payload, `repository.full_name`, with no cross-check against `repository.owner.login`: [4](#0-3) 

Because `verify_signature` only proves "this body was HMAC-signed with organization A's secret," but the handler trusts `repository.full_name` from the very same attacker-influenced body to pick which repository/stack to act on, an actor who legitimately controls (and thus knows the `webhook_secret` of) one onboarded organization "A" can craft a payload where `repository.owner.login = "A"` (so signature check passes) while `repository.full_name` points at a completely different organization/repository "B" that is also tracked by the same Shipit instance. The binding broken is exactly the one called out in scope: *"an organization that authenticated versus the repository that is written."*

The clearest exploitable handler is `StatusHandler`, which trusts `sha`/`state`/`context` from the payload and writes a `Status` for any commit in the datastore matching that SHA, with no repository/stack scoping at all: [5](#0-4) 

Commit statuses gate whether pull requests are eligible for the merge queue and whether commits are deployable (`required_statuses`, `blocking_statuses`, used by `MergeRequest::StatusChecker` / `ProcessMergeRequestsJob`): [6](#0-5) [7](#0-6) 

By forging a "success" status for a required CI context on an arbitrary victim commit SHA (which the attacker can learn from the victim's public repo or PR), the org-A attacker can make an unrelated organization's pull request appear to pass all required checks, letting Shipit auto-merge it via the merge queue, or make an otherwise untested commit appear deployable.

### Impact Explanation
This breaks a deployment-trust boundary between tenants of the same Shipit instance: possession of a legitimate, low-privilege webhook secret for one onboarded GitHub organization is sufficient to inject fabricated CI status data for any other organization/repository tracked by the instance, which can cause an **unauthorized merge** (via the merge queue bypassing required status checks) — matching the Critical-tier impact "unauthorized deploy, rollback or merge."

### Likelihood Explanation
Exploitation requires only knowledge of a `webhook_secret` for one organization already configured in a multi-tenant Shipit deployment (i.e., an org admin who legitimately set up their own GitHub App/webhook for Shipit, per `docs/setup.md`), plus the target commit SHA and required status context name of a victim repository, both of which are typically public information (GitHub commit SHAs, CI context names). No Shipit session, `ApiClient` token, or GitHub App private key is required — only a raw HTTP POST with a correctly computed HMAC using an org secret the attacker legitimately possesses.

### Recommendation
Bind the verified organization to the repository being acted upon: after computing `repository_owner` for signature verification, re-derive/validate that `repository.full_name`'s owner segment matches `repository_owner` before dispatching to any handler, or have `Handler#repository_name` reject processing when the payload's `repository.owner.login` does not match the organization whose secret validated the signature.

### Proof of Concept
1. Shipit instance configures two organizations, `attacker-org` (secret known to the attacker, who administers that org's GitHub App) and `victim-org` (an unrelated org tracked by the same instance), per `config/secrets.*.yml`.
2. Attacker computes `sha1=HMAC(webhook_secret_of_attacker_org, body)` for a crafted body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. POST to `/webhooks` with header `X-Github-Event: status` and the computed `X-Hub-Signature`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully because the signature matches `attacker-org`'s secret. [1](#0-0) 
5. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching the victim commit in `victim-org/victim-repo` — and calls `commit.create_status_from_github!(params)`, injecting a forged "success" status. [5](#0-4) 
6. If `ci/required-check` is in `victim-org`'s `required_statuses`, the victim's pending pull request now passes `all_status_checks_passed?`/`reject_unless_mergeable!` checks and can be auto-merged by `ProcessMergeRequestsJob`. [8](#0-7)

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

**File:** config/secrets.development.shopify.yml (L5-18)
```yaml
github:
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

**File:** app/models/shipit/merge_request.rb (L155-163)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end

```

**File:** app/models/shipit/merge_request.rb (L193-217)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end

    def waiting?
      WAITING_STATUSES.include?(merge_status)
    end

    def need_revalidation?
      timeout = stack.cached_deploy_spec&.revalidate_merge_requests_after
      return false unless timeout

      (revalidated_at + timeout).past?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-31)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
```
