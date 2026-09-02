### Title
Webhook signature verification is keyed on `repository.owner.login`, but every event handler acts on the unauthenticated `repository.full_name` field, letting a payload "authenticated" for one GitHub organization drive writes against a stack belonging to a different repository/organization - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check against using `repository.owner.login` (or `organization.login`) from the JSON body, but the handlers that actually mutate state (`PushHandler`, `StatusHandler`, `PullRequest::*Handler`) resolve the target `Repository`/`Stack` using a different field in the same body, `repository.full_name`. Nothing binds these two fields together cryptographically or programmatically, so the "org whose secret verified the request" and "the repository the request acts on" can diverge. Combined with `GitHubApp#verify_webhook_signature` returning `true` unconditionally when an organization has no `webhook_secret` configured (a documented, valid configuration state), an unauthenticated attacker can trigger this divergence with zero credentials.

### Finding Description
The binding that should hold is:

`organization authenticated by verify_signature == organization that owns the repository the handlers act on`

`WebhooksController#verify_signature` computes the verifying organization from the payload itself, not from any external/trusted context: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end
...
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up per-organization config, and if that organization has no `webhook_secret` configured, `verify_webhook_signature` short-circuits to `true`: [2](#0-1) 

The docs and shipped fixture configs explicitly allow `webhook_secret` to be `nil`/blank for a configured organization, e.g. `test/dummy/config/secrets_double_github_app.yml` (`webhook_secret: # nil` for both `OrgOne` and `OrgTwo`) and `docs/setup.md`'s example. This is a supported deployment shape (multi-org Shipit installs where not every org has set a secret yet, or intentionally left blank), not a misconfiguration outside the engine's own code.

Once `verify_signature` passes, `WebhooksController#create` dispatches the *entire raw payload* to handlers, and those handlers derive the repository/stack to act on from a completely different, also attacker-controlled field: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` uses this to look up stacks and call `stack.sync_github`: [4](#0-3) 
`StatusHandler` uses `params.sha` (not scoped to a repo at all) to create commit statuses on ANY matching commit across the whole install: [5](#0-4) 
Pull-request handlers (`opened_handler.rb`, `closed_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`, `assigned_handler.rb`, `edited_handler.rb`) all resolve `repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, e.g. [6](#0-5) , and then archive/unarchive/provision Review Stacks based on that repository — driving `ReviewStack` provisioning/deprovisioning (`stack.deprovision`, `ReviewStackProvisioningQueue.add`) which runs real infrastructure-affecting task steps from `shipit.yml`.

Because `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled strings in the same unauthenticated (pre-verification) JSON body, and verification of the former does not constrain the latter, a request that is deemed "verified" for organization A can carry a `repository.full_name` pointing at a stack that belongs to organization B.

### Impact Explanation
This is a real-world instance of the report's bug class: "amount acted upon != amount covered by the check" — here, "organization verified" != "repository/stack acted upon." Concretely, if any organization configured on the instance has `webhook_secret` blank (a documented supported state), an unauthenticated attacker can:
- Send a forged `status` event with `repository.owner.login` set to the secret-less org (bypassing the signature check entirely) while `sha` matches a commit belonging to a stack under a *different, secret-protected* organization, injecting fabricated commit statuses (`Commit#create_status_from_github!`) for that unrelated repository.
- Send forged `push`/`pull_request` events the same way to trigger `stack.sync_github`, archive/unarchive Review Stacks, or provision/deprovision Review Stacks (running deploy/rollback-adjacent task steps) for a stack that belongs to a different, victim organization/repository — all without ever passing a valid signature for that victim org.

This crosses the "organization authenticated versus the repository that is written" boundary called out in scope, and manifests as unauthorized state changes (fake commit statuses, unauthorized Review Stack provisioning/deprovisioning) on stacks the attacker was never authenticated against — i.e., cross-repository writes performed by an unprivileged, unauthenticated caller.

### Likelihood Explanation
Likelihood is contingent on deployment configuration: it requires at least one configured GitHub organization on the instance to have `webhook_secret` unset/blank. This is not a hypothetical misconfiguration — it's explicitly modeled in the engine's own fixtures/docs (`secrets_double_github_app.yml`, `docs/setup.md`) as a valid state, and is realistic during incremental onboarding of a multi-org Shipit install (each org's GitHub App webhook secret is typically configured after the app is created). Given that state, exploitation requires no credentials, no session, and no GitHub write access — only knowledge of a target commit SHA or repository full_name, both of which are typically public information.

### Recommendation
Do not use payload-supplied fields to select the verification secret independently from the fields used to determine the acted-upon repository. Concretely:
- After signature verification succeeds for organization X, re-derive/validate that `repository.full_name`'s owner matches the same organization X (reject the event if they differ), instead of trusting `full_name` unconditionally in every handler.
- Treat a missing/blank `webhook_secret` as "reject all webhooks for this organization" rather than "accept all webhooks unconditionally" in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Given a Shipit instance configured with two organizations, `OrgOne` (no `webhook_secret` set) and `OrgTwo` (a real, secret-protected repo containing stack `OrgTwo/victim-repo`):

1. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<sha of a commit belonging to OrgTwo/victim-repo>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" }
}
```
2. `WebhooksController#verify_signature` computes `repository_owner` = `"OrgOne"`, looks up `Shipit.github(organization: "OrgOne")`, and since `OrgOne` has no `webhook_secret`, `verify_webhook_signature` returns `true` regardless of the (missing/garbage) `X-Hub-Signature` header — request passes verification.
3. `WebhooksController#create` dispatches the payload to `Shipit::Webhooks.for_event('status')`, which runs `StatusHandler#process`, which finds `Commit.where(sha: params.sha)` — a commit under `OrgTwo/victim-repo` — and calls `create_status_from_github!`, injecting a fabricated "success" status for a repository whose organization's webhook secret was never checked. [7](#0-6) [2](#0-1) [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
