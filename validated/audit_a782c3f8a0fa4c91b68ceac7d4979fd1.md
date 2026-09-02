### Title
Cross-tenant ReviewStack archival via `repository.full_name`/`repository.owner.login` divergence in `pull_request` webhooks - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify against using `repository.owner.login` (or `organization.login`), but `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler` resolves the target `Repository`/`ReviewStack` scope using the independent, unrelated `repository.full_name` field. Since the attacker fully controls the raw JSON body they sign, they can compute a valid signature for their own org while naming an arbitrary victim `full_name`, causing the handler to archive/deprovision a `ReviewStack` belonging to an org they never authenticated as.

### Finding Description
The broken binding: the question requires `repository_owner (verified by HMAC) == owner_of(stack acted upon)`. In this codebase these are two independent fields of the same JSON body:

- `WebhooksController#repository_owner` reads `params.dig('repository', 'owner', 'login')` and uses it to pick the `GitHubApp`/secret for signature verification: `Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(signature, request.raw_post)`. [1](#0-0) [2](#0-1) 

- `ClosedHandler#repository` resolves the acted-upon repository purely from `params.repository.full_name`, with no cross-check against the verified `repository.owner.login`/organization used in `verify_signature`: [3](#0-2) 

- `Repository.from_github_repo_name` splits `full_name` and does a plain `find_by(owner:, name:)` lookup, again independent of any verified organization: [4](#0-3) 

- `ReviewStackAdapter#archive!`/`#stack` then finds and mutates the `ReviewStack` scoped to that (attacker-chosen) repository by `environment: "pr#{params.number}"`, deprovisioning and archiving it: [5](#0-4) [6](#0-5) 

Root cause: `verify_signature` authenticates "this request originated from an org whose secret matches `repository.owner.login`", but the handler trusts a completely different, unauthenticated field (`repository.full_name`) to decide which tenant's data to mutate. HMAC signing covers the whole raw JSON body, so this is not exploitable by a real GitHub-originated webhook (GitHub would sign a payload with consistent `owner.login`/`full_name`), but it is fully exploitable by any actor who can compute a valid HMAC for the payload — which per the threat model includes an operator of their own tenant/org in this multi-tenant Shipit deployment (`Shipit.github(organization:)` supports per-org secrets, as shown in `secrets_double_github_app.yml`/`config/secrets.development.shopify.yml` and `Shipit#github_app_config`). Such an attacker legitimately knows their own org's `webhook_secret` (it's the secret they configured for their own GitHub App/org), and directly `POST /webhooks` a hand-crafted body:
```json
{
  "action": "closed",
  "number": 7,
  "pull_request": { ... "user": {"login": "attacker"} ... },
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } },
  "sender": { "login": "attacker" }
}
```
signed with `attacker-org`'s own secret. `verify_signature` passes (verified against attacker-org's own secret), `drop_unhandled_event`/`ExplicitParameters` schema in `ClosedHandler.params` only validate field shapes, not cross-field consistency, `respond_to_pull_request_closed?` only checks `action == "closed"`. None of these guards check that `repository.full_name`'s owner matches the verified `repository_owner`. If `victim-org/victim-repo` has a `ReviewStack` with `environment == "pr7"`, it gets `deprovision`ed and `archive!`d.

### Impact Explanation
This is a payload for one repository (attacker's own, authenticated by their own org's secret) mutating another repository/tenant's (`victim-org/victim-repo`) `ReviewStack` — `stack.remove_from_provisioning_queue`, `stack.deprovision`, and `stack.archive!` are all invoked on the victim's real infrastructure record, with no relationship between the verifying org and the owning org. This matches the "Critical" category: "a payload for one repository mutating another's stack" and constitutes an unauthorized deprovision/archive of a victim's environment. It is repeatable against any victim repository/PR-number combination as long as the attacker can guess or observe a live `pr{number}` ReviewStack (PR numbers are small integers, easily brute-forced or observed publicly on GitHub), and it works identically for `LabeledHandler`/`UnlabeledHandler`/`OpenedHandler`/`ReopenedHandler`, which follow the same `repository.full_name`-vs-`repository.owner.login` pattern.

### Likelihood Explanation
Requires: (1) the Shipit deployment configured for multi-tenant GitHub Apps (`Shipit.github(organization:)` per-org secrets, a documented supported configuration — see `docs/setup.md` "Using Multiple Github Applications"), (2) the attacker controls one such onboarded org (with review stacks / PR-based provisioning enabled) and thus knows its own `webhook_secret`, and (3) a victim repo/org with a `ReviewStack` whose `environment` (`pr{number}`) collides with an attacker-chosen number. Cost to the attacker is trivial: one HTTP POST with a correctly-computed HMAC using a secret they legitimately possess. No Shipit session, API token, or cross-org secret is needed.

### Recommendation
In `ClosedHandler` (and the other `pull_request` handlers `OpenedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`), verify that the org derived from `params.repository.full_name` matches the verified `repository_owner`/organization used in `WebhooksController#verify_signature` before resolving `repository`/`review_stack`. Concretely, pass the verified organization (already computed in the controller) through to the handler and assert `params.repository.full_name.split('/').first.casecmp(verified_organization) == 0` before proceeding, rejecting (or logging and dropping) the event otherwise.

### Proof of Concept
Minitest plan (e.g., in `test/controllers/webhooks_controller_test.rb` or a dedicated cross-tenant test):
```ruby
test "pull_request closed webhook cannot archive another org's review stack" do
  # Setup: multi-tenant github config with distinct secrets for 'attacker-org' and 'victim-org'
  # (mirrors test/dummy/config/secrets_double_github_app.yml)
  victim_repo = Shipit::Repository.create!(owner: 'victim-org', name: 'victim-repo', review_stacks_enabled: true, provisioning_behavior: :allow_all)
  victim_stack = Shipit::ReviewStack.create!(repository: victim_repo, environment: 'pr7', branch: 'feature')

  body = {
    action: 'closed',
    number: 7,
    pull_request: { id: 1, number: 7, url: 'u', title: 't', state: 'closed', additions: 1, deletions: 1,
                     head: { sha: 'a' * 40, ref: 'feature' }, user: { login: 'attacker' },
                     assignees: [], labels: [] },
    repository: { full_name: 'victim-org/victim-repo', owner: { login: 'attacker-org' } },
    sender: { login: 'attacker' }
  }.to_json

  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', attacker_org_webhook_secret, body)}"

  assert_not victim_stack.reload.archived?

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = signature
  post :create, body: body, as: :json

  assert_response :ok
  assert victim_stack.reload.archived?, "victim-org's stack should NOT have been archived by an attacker-org-signed payload"
end
```
The equality to assert both before and after: `repository_owner_verified_by_signature == organization_of(stack_that_gets_archived)`. Before the fix, `attacker-org != victim-org` yet the victim stack archives (bug reproduced). After the fix, the handler should reject/no-op because the org derived from `full_name` (`victim-org`) does not match the verified `repository_owner` (`attacker-org`).

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-59)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-35)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end

          def find_or_create!
            stack || create!
          end

          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L96-98)
```ruby
          def environment
            "pr#{params.number}"
          end
```
