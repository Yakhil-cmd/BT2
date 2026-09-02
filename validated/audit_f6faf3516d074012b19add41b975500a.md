### Title
Webhook signature check authenticates the `repository.owner.login` organization while all handlers act on the unrelated `repository.full_name` field, letting an unauthenticated payload target any stack when one configured organization has no `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which `Shipit::GithubApp` config to validate the HMAC signature against using only the organization named in the payload: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` on that app config short-circuits to `true` whenever no `webhook_secret` is configured for that organization: [3](#0-2) 

The webhook secret is documented as optional in a multi-organization deployment (`docs/setup.md` explicitly lists `webhook_secret:` as `# nil` per-org, and calls it "optional" for single-org setups), so it is a supported, expected configuration state, not a misconfiguration.

Once verification passes (or is skipped), the raw JSON body is handed unmodified to every registered handler. All handlers resolve the target `Stack`/`Repository` via a completely different field, `repository.full_name`, in `Handler#repository_name`/`#stacks`: [4](#0-3) 

Nothing ties `repository.owner.login` (used to select the signing organization/secret) to `repository.full_name` (used to select which repository's data is mutated). An attacker can therefore construct a JSON body where `repository.owner.login` names an organization that has no `webhook_secret` configured, while `repository.full_name` names an entirely different, protected repository belonging to a different organization. Signature verification passes trivially (`return true unless webhook_secret`), yet the handler acts on the victim repository.

For example `PushHandler` uses `repository_name`/`stacks` to look up stacks and calls `sync_github`: [5](#0-4) 

and `StatusHandler` writes commit statuses for any commit whose sha is supplied, independent of repository at all: [6](#0-5) 

The controller itself never cross-checks these two identity fields: [7](#0-6) 

### Impact Explanation
This breaks the trust binding "organization that authenticated == repository that is written." An unprivileged, unauthenticated network attacker (no `webhook_secret`, no `ApiClient` token, no GitHub App key needed) can forge arbitrary webhook payloads targeting any `Stack` in the Shipit instance, as long as the Shipit instance is configured for more than one GitHub organization and at least one of them has no `webhook_secret` set (an explicitly supported/documented configuration). This yields cross-repository writes: forcing `sync_github` on unrelated stacks, injecting fabricated commit statuses via `StatusHandler`, creating arbitrary teams/users via `MembershipHandler`, or manipulating pull-request/check-suite state for repositories the attacker has no relationship with — none of which the attacker authenticated for.

### Likelihood Explanation
Likelihood is high in any multi-organization Shipit deployment where at least one configured GitHub App/org omits the optional `webhook_secret` (a state the documentation itself presents as normal), since the only requirement is crafting an HTTP POST with the right JSON structure and an `X-Github-Event` header — no credentials of any kind are needed for the org lacking a secret.

### Recommendation
Cross-validate that the organization used to select the verifying `GithubApp` (`repository.owner.login` / `organization.login`) matches the organization implied by `repository.full_name` before dispatching to handlers, and reject the request if they diverge. Additionally, consider requiring `webhook_secret` to be mandatory (or rejecting silently-unsigned requests for organizations configured without one) so that an "optional secret" on one organization cannot be leveraged to bypass verification for events referencing a different organization's repositories.

### Proof of Concept
1. Shipit is configured with two organizations, e.g. `OrgA` (no `webhook_secret` set, per the documented optional configuration) and `OrgB` (protected, has an active `Stack`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: 'OrgA')` and `verify_webhook_signature` returns `true` immediately because `OrgA` has no `webhook_secret` (app/controllers/shipit/webhooks_controller.rb:24-30, lib/shipit/github_app.rb:76-83) — no signature header is even required.
4. `PushHandler#process` resolves `stacks` via `repository.full_name == "OrgB/victim-repo"` (app/models/shipit/webhooks/handlers/handler.rb:32-38) and invokes `sync_github(expected_head_sha: "deadbeef...")` on `OrgB`'s stack, an action the attacker never authenticated to perform.

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
