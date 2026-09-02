### Title
Webhook signature is verified against the organization derived from the payload's `repository.owner.login`, but `StatusHandler` writes commit status to any commit matching the SHA globally, with no repository/organization scoping - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against based on `repository_owner`, a field read directly out of the *unverified* JSON payload. [1](#0-0)  Once the signature check passes for that organization, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, whose `process` method looks up commits purely `Commit.where(sha: params.sha)` — with no filter on repository, stack, or organization at all — and writes a new GitHub-reported status onto every matching commit. [2](#0-1) 

### Finding Description
This mirrors the LockZap.sol bug class: a permission/authentication decision is bound to one field (the organization whose `webhook_secret` validated the signature), while the actual state-changing operation is keyed off a completely different, unrelated field (`sha`) that isn't covered by that same trust boundary.

Concretely, in a Shipit deployment configured for multiple GitHub organizations (a documented, supported configuration — see `docs/setup.md` "Using Multiple Github Applications" and `Shipit.github_app_config`), each organization has its own independent `webhook_secret`. [3](#0-2)  `verify_signature` picks the secret using `repository_owner`, which is read straight from the request body before any signature check occurs:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

An attacker who legitimately owns/administers one configured GitHub organization in a multi-org Shipit installation (Org A) knows Org A's `webhook_secret` because they configured it themselves. They can then submit a raw `status` event to `/webhooks` with:
- `repository.owner.login = "OrgA"` (so `verify_signature` authenticates using Org A's own secret, which the attacker controls and can correctly HMAC-sign)
- `sha` set to a commit hash that actually belongs to a stack under a completely different, victim organization (Org B)

Because `StatusHandler#process` never checks that the commit's stack/repository belongs to the organization that authenticated the request, it will happily attach the forged CI status to the victim's commit:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

`create_status_from_github!` → `Commit#add_status` recomputes `deployable?` and, if the commit becomes `pending` or `success`, schedules continuous delivery and merge processing:
```ruby
stack.schedule_merges if new_status.pending? || new_status.success?
``` [5](#0-4)  and elsewhere status transitions trigger `ContinuousDeliveryJob` for stacks with `continuous_deployment: true`. [6](#0-5) 

The binding that should hold — "organization whose signature authenticated the request == organization that owns the repository/commit being mutated" — is broken. `sha` is an attacker-observable, non-secret public value (visible on GitHub, in webhook payloads, in the Shipit UI itself), so any org-boundary attacker who administers even one configured GitHub organization can target arbitrary commits belonging to any other organization's stacks tracked by the same Shipit instance.

### Impact Explanation
By forging a `success` status for a required CI context on a victim stack's pending commit, an attacker can:
- Satisfy `Commit#deployable?` checks and merge-queue "all status checks passed" gating (`MergeRequest#all_status_checks_passed?` relies on the same `Status` records), potentially triggering an **unauthorized merge** of a queued pull request in a repository/organization the attacker does not control.
- Trigger `ContinuousDeliveryJob` for stacks with continuous deployment enabled, resulting in an **unauthorized deploy** of a commit whose real CI never actually passed.
- More generally, this is a **cross-organization write** into `Status`/`Commit` records that should only be writable by the organization whose GitHub App/webhook is authorized for that repository.

This satisfies the "unauthorized deploy, rollback, or merge" and "cross-repository writes" impact bar defined for this analysis.

### Likelihood Explanation
Requires only that Shipit be configured with more than one GitHub organization (a documented, supported feature) and that the attacker control (or have been granted) one of those organizations' GitHub App installations — i.e., they know that org's own `webhook_secret`, which they set themselves when configuring their org's app. No access to the victim organization, no GitHub credentials of the victim, and no Shipit user session are needed; the attacker only needs to know a target commit SHA in the victim repository, which is public information (visible via GitHub, git history, or the Shipit stack timeline). This is a realistic tenant-isolation failure in any single Shipit deployment serving multiple organizations.

### Recommendation
`StatusHandler` (and any other handler that trusts payload-derived identifiers without re-deriving them from the authenticated context) must scope its lookup to the repository/organization that was actually verified by `verify_signature`, e.g. by joining `Commit → Stack → Repository` and filtering on `repository.owner == repository_owner` (or equivalently passing the verified organization down into the handler and requiring it match `stack.repository.owner`) before applying any status update. More generally, every webhook handler should validate that the `repository.full_name`/`owner` referenced in the payload matches the organization whose secret validated the request, rather than trusting `sha` (or any other payload field) as an implicit scoping mechanism.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications").
2. Attacker administers `OrgA`'s GitHub App and therefore knows `OrgA`'s `webhook_secret`.
3. Attacker identifies a pending commit SHA `deadbeef...` in an `OrgB`-owned stack that is required to pass CI context `ci/required` before merge/deploy (public information, e.g. visible via Shipit's UI or GitHub for that PR/commit).
4. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`, body:
```json
{
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/required",
  "repository": { "owner": { "login": "OrgA" } }
}
```
signed with `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>`.
5. `verify_signature` selects `Shipit.github(organization: 'OrgA')` and validates successfully (attacker knows this secret). [7](#0-6) 
6. `StatusHandler#process` matches `Commit.where(sha: 'deadbeef...')` — the `OrgB` commit — and creates a `success` `Status` on it, with no check that the commit belongs to `OrgA`. [2](#0-1) 
7. If `OrgB`'s stack has `continuous_deployment: true` or an active merge queue relying on that CI context, this forged status can trigger an unauthorized deploy or merge of the `OrgB` commit.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** lib/shipit/engine.rb (L46-51)
```ruby
      if Shipit.github.oauth?
        OmniAuth::Strategies::GitHub.configure(path_prefix: '/github/auth')
        app.middleware.use(OmniAuth::Builder) do
          provider(:github, *Shipit.github.oauth_config)
        end
      end
```

**File:** app/models/shipit/commit.rb (L374-384)
```ruby
      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```
