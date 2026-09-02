### Title
Webhook signature check authenticates one GitHub organization while `StatusHandler`/`PushHandler` act on commits/stacks belonging to a completely different, unchecked repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify the HMAC signature against using an attacker-supplied field (`repository.owner.login` / `organization.login`), while the actual handlers that mutate state (`StatusHandler`, `PushHandler`) resolve their target purely from other attacker-supplied fields (`sha`, `repository.full_name`) with no cross-check that they refer to the organization that was actually verified.

### Finding Description
`WebhooksController#verify_signature` computes the organization to authenticate against directly from the untrusted JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the configured `GithubApp` for that organization, and `verify_webhook_signature` is configured **per organization** — critically, if that organization has no `webhook_secret` configured, verification is bypassed entirely: [3](#0-2) 

The setup docs explicitly state `webhook_secret` is optional, and the shipped secrets templates default it to `nil`: [4](#0-3) [5](#0-4) 

So in any multi-organization Shipit deployment (the engine explicitly supports configuring several GitHub orgs, see `test/dummy/config/secrets_double_github_app.yml`) where at least one configured organization has no `webhook_secret`, an attacker can pick that organization's login for `repository.owner.login`/`organization.login` and `verify_signature` passes unconditionally — no valid signature is required at all.

Once past `verify_signature`, the actual handlers never re-check that the acted-upon repository belongs to the organization that was used for verification:
- `PushHandler`/`Handler#stacks` resolve the target `Stack` purely via `payload.dig('repository', 'full_name')`, independent of `repository_owner`: [6](#0-5) [7](#0-6) 
- `StatusHandler` is even less scoped: it updates the CI status of **any** commit matching `sha` globally, with no repository/organization filter whatsoever: [8](#0-7) 

This breaks the intended equality `verified_organization == acted_upon_repository_owner`. The signature check only proves "the sender knows organization X's secret (or X has none)"; it proves nothing about the `repository.full_name`/`sha` fields that the handlers actually trust to select which `Stack`/`Commit` to mutate.

### Impact Explanation
An attacker who knows (or guesses, e.g. via a low-value personal org they registered against the same Shipit instance, or any org purposefully left unsecured per the documented "optional" secret) an organization with no `webhook_secret` can:
1. Send an unsigned `status` event naming any `sha`, `state: success` for a commit belonging to a totally unrelated, secured victim organization's stack — since `StatusHandler` performs no ownership check at all. This can flip a required CI check to green for a commit that never actually passed CI, and if that stack has `continuous_deployment` enabled, causes an **unauthorized deploy** of attacker-chosen code.
2. Send an unsigned `push` event whose `repository.full_name` names a victim's stack to trigger `stack.sync_github`, forcing state changes (github sync) on a repository never authenticated for.

This matches the Critical impact bar of "an unauthorized deploy" via a webhook payload/signature binding break, without requiring an `ApiClient` token, session, or GitHub write access — only knowledge that one org among many configured on the instance is unsecured (the engine explicitly allows and documents this configuration).

### Likelihood Explanation
Requires a multi-organization Shipit deployment where at least one org's `webhook_secret` is left blank (explicitly supported/documented as optional) while another org holds the actual victim stacks. This is a realistic operational configuration (e.g., staging/sandbox orgs without secrets alongside production orgs that do have secrets), and the attacker needs no credentials, only the ability to send an HTTP POST to `/webhooks` with a crafted JSON body naming the unsecured org.

### Recommendation
- Reject webhook payloads unless `repository.full_name`'s owner matches the organization used to select the verification secret (`repository_owner`).
- Do not allow `verify_webhook_signature` to silently pass when `webhook_secret` is blank for one org while other orgs are configured with secrets on the same instance; require the same secret/verification policy across all configured GitHub Apps, or explicitly disallow mixed secured/unsecured org configurations.
- Scope `StatusHandler`'s `Commit.where(sha: params.sha)` lookup to commits belonging to the repository named in the payload (and validate that repository against the verified organization) instead of matching `sha` globally.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs: `victim-org` (has stacks, `webhook_secret: <real-secret>`) and `attacker-org` (`webhook_secret: ` blank, e.g., mirroring `test/dummy/config/secrets_double_github_app.yml`'s `OrgTwo`).
2. POST to `/webhooks` with header `X-Github-Event: status` and no valid `X-Hub-Signature`, body:
```json
{
  "sha": "<target commit sha of a victim-org stack under required CI>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
3. `verify_signature` resolves `repository_owner` = `attacker-org`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request is accepted with no valid signature.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a "success" status on the victim-org's commit, with no check that the commit belongs to `attacker-org`.
5. If the victim stack has `continuous_deployment` enabled and this was the last blocking required status, `ContinuousDeliveryJob` triggers a deploy of that commit — an unauthorized deploy achieved without ever possessing `victim-org`'s webhook secret.

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

**File:** docs/setup.md (L119-121)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.

**`github.private_key`** In your GitHub App settings, on the `General` section, you can generate and download a private key. You will end up with a `.pem` file and you need to copy it's content here.
```

**File:** template.rb (L68-74)
```ruby
      github:
        domain: # defaults to github.com
        bot_login:
        app_id:
        installation_id:
        webhook_secret:
        private_key:
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
