### Title
Webhook signature is verified against the organization named in `repository.owner.login`, while the stack actually mutated is selected by the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub organization's webhook secret to check the signature against using `repository_owner` (derived from `repository.owner.login` or `organization.login`), while every event `Handler` resolves the stack to actually write to using a completely different payload field, `repository.full_name`. Because organizations can be configured without a `webhook_secret`, and because these two fields are never cross-checked, a payload can be authenticated as belonging to a secret-less (or attacker-controlled) organization while its actual write target (`repository.full_name`) points at a stack belonging to a different, secret-protected organization.

### Finding Description
`verify_signature` selects the GitHub App config solely from the organization login and unconditionally treats a missing secret as "verified": [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` short-circuits to `true` whenever `webhook_secret` is blank for that organization: [3](#0-2) 

Once the request passes `verify_signature`, `WebhooksController#create` dispatches the entire raw payload to handlers based only on `X-Github-Event`, without re-validating that `repository.full_name`'s owner matches the organization that was actually verified/authenticated (`repository_owner`): [4](#0-3) 

Every handler then resolves the stack(s) to mutate purely from `repository.full_name`, a value taken from the same untrusted JSON body but never tied to `repository_owner`: [5](#0-4) [6](#0-5) 

This is a binding break in the "organization that authenticated versus the repository that is written" class: the equality that should hold is `organization_used_for_signature_check == owner(repository.full_name)`, but nothing in the controller or `Handler` base class enforces it. The engine explicitly supports multiple GitHub organizations/apps configured simultaneously (see the multi-org fixture `test/dummy/config/secrets_double_github_app.yml`), and each organization's `webhook_secret` is independently optional (`@webhook_secret = @config[:webhook_secret].presence`), so it is entirely plausible in a real deployment that one configured organization has no secret set (e.g. a newly onboarded org, or one intentionally left open for testing) while another configured organization does have a secret and hosts stacks the attacker should not be able to touch.

### Impact Explanation
If any organization configured on the Shipit instance has a blank `webhook_secret`, an attacker can send an arbitrary unsigned POST to `/webhooks` with `organization.login` (or `repository.owner.login`) set to that secret-less organization, but with `repository.full_name` set to any other tracked repository (e.g. one belonging to a fully-protected organization). `verify_signature` passes trivially (secret is blank ⇒ `verify_webhook_signature` returns `true`), and the `PushHandler`/`StatusHandler`/etc. then act on the stack resolved from the forged `repository.full_name`. For the `push` event this triggers `stack.sync_github(expected_head_sha:)`, letting an unauthenticated party drive `GithubSyncJob` against a stack in an organization they have no relationship with, and for `status`/`check_suite` events it can fabricate CI state used to gate `deployable?`/continuous deployment. This can result in unauthorized deploy triggers or corrupted deployability state on a cross-organization stack, matching the High-impact "unauthenticated read of stack state" / "unauthorized deploy" categories.

### Likelihood Explanation
Requires only that at least one configured GitHub organization on the instance has no `webhook_secret` set (an explicitly supported, documented configuration in `docs/setup.md`/`template.rb`), which is realistic for multi-tenant Shipit deployments during onboarding or for internal/test organizations. No credentials, GitHub App keys, or Shipit session are needed — only knowledge that such an organization exists and is configured on the instance, and knowledge of another tracked `owner/repo` full name (easily discoverable, e.g. from the Shipit UI).

### Recommendation
In `WebhooksController`, derive the target repository/stack scope from the same trusted, verified field used for the signature check, and reject any request whose event payload's `repository.full_name` owner disagrees with `repository_owner`. Concretely: after `verify_signature`, assert `payload.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first` (or better, always look up the organization from `full_name` and re-verify against that organization's secret), and treat a blank `webhook_secret` as "verification required to be explicitly configured" rather than an implicit bypass — i.e. require an explicit opt-in flag instead of `secret.blank? => true`.

### Proof of Concept
1. Configure Shipit with two organizations: `orgA` (no `webhook_secret` set) and `orgB` (has a real `webhook_secret`, and owns a tracked stack `orgB/victim-repo`).
2. Send, without any `X-Hub-Signature` header (or any arbitrary value):
```
POST /webhooks
X-Github-Event: push

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "orgB/victim-repo", "owner": { "login": "orgA" } }
}
```
3. `repository_owner` resolves to `"orgA"`; `Shipit.github(organization: "orgA")` has a blank secret, so `verify_webhook_signature` returns `true` unconditionally — the request passes verification with no valid signature at all.
4. `PushHandler#process` resolves `stacks` from `repository.full_name = "orgB/victim-repo"`, and calls `stack.sync_github(expected_head_sha: params.after)` on `orgB`'s stack, despite the request never being authenticated by `orgB`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
