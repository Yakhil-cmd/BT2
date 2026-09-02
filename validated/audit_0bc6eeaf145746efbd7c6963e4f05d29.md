## Title
Webhook signature verification authenticates the wrong entity to the write target — cross-repository forged CI status / stack writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App secret to validate a webhook's HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the *unverified* JSON body. Every webhook handler, however, resolves the actual `Repository`/`Stack` to mutate using a *different* field of that same unverified body: `repository.full_name`. Because the signature only proves the request was signed with the secret belonging to whichever organization the attacker names in `repository.owner.login`, and never checks that this organization actually owns the repository named in `repository.full_name`, any tenant holding one valid, legitimately-configured webhook secret in a multi-org Shipit install can forge signed webhooks that write to a completely different organization's stacks.

### Finding Description
`verify_signature` picks the app/secret using attacker-controlled data, then validates the *whole raw body* against that secret [1](#0-0)  with the org key coming straight from the JSON payload [2](#0-1) .

`GitHubApp#verify_webhook_signature` only proves "this body was HMAC-signed with organization X's secret" — it says nothing about which repository the body's other fields refer to [3](#0-2) .

Multi-organization installs are an explicitly supported, documented configuration where each org has its own independent `webhook_secret` [4](#0-3) , resolved via `Shipit.github(organization:)` / `github_app_config` [5](#0-4) .

Every default handler, though, determines the target `Repository`/`Stack` from the unrelated `repository.full_name` field of the same payload: [6](#0-5) . This is used by `StatusHandler`, which writes a `Status` on any commit matching `params.sha` with an attacker-fully-controlled `state`/`context`/`description`/`target_url` [7](#0-6) , and by `PushHandler`, which enqueues a real GitHub sync for the target stack [8](#0-7) .

**The broken binding, stated as an equality that the code fails to enforce:**
`organization that authenticated the request` (`repository.owner.login` used to select the webhook secret) `== organization that owns the repository being written` (`repository.full_name` used by the handler). Nothing in `WebhooksController` or `Handler` checks these two fields agree.

### Impact Explanation
An attacker who administers any one legitimately onboarded, lower-trust GitHub organization/App in a multi-org Shipit deployment (and therefore knows that org's own `webhook_secret`, which they configured themselves when creating their GitHub App) can POST directly to `/webhooks` with:
- `repository.owner.login` = their own org (so `Shipit.github(organization: ...)` picks their known secret and the HMAC check passes)
- `repository.full_name` = `victim-org/victim-repo` (so the handler resolves and mutates the victim's `Stack`)

This lets the attacker:
- Forge a `status` event to write an arbitrary `Status` (`state: "success"`, arbitrary `context`) onto any commit SHA in the victim's stack, which can satisfy `ci.require` gates or merge-queue requirements and lead to an **unauthorized merge/deploy**.
- Forge a `push` event to trigger `GithubSyncJob`/`ContinuousDeliveryJob` behavior on a victim stack, interfering with its deploy pipeline.

This satisfies the Critical impact bar ("unauthorized deploy, rollback, or merge" / "cross-repository writes") without needing any Shipit session, API token, or the victim's own webhook secret.

### Likelihood Explanation
Requires only: (a) Shipit configured for multiple GitHub organizations (a documented, supported configuration, not a misconfiguration), and (b) the attacker controlling one such organization's own GitHub App/webhook secret — no privileged Shipit credential, no access to the victim org, and no signature-forging is needed since the attacker signs with a secret they legitimately possess.

### Recommendation
After signature verification succeeds, re-derive the organization from the same trusted source used for verification and assert it matches the owner encoded in `repository.full_name` (or resolve the target `Repository`/`Stack` only within the authenticated organization's scope) before dispatching to handlers. Reject the webhook if `repository.owner.login`/`organization.login` does not match the owner segment of `repository.full_name`.

### Proof of Concept
1. Configure Shipit with two orgs in `config/secrets.yml`: `attacker-org` (secret `S_A`, owned/configured by the attacker) and `victim-org` (secret `S_V`, unknown to the attacker), per the multi-org setup docs.
2. Attacker builds a `status` webhook payload:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S_A, body)` using their own known secret `S_A` and sends `POST /webhooks` with header `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies successfully against `S_A` (`lib/shipit/github_app.rb#verify_webhook_signature`).
5. `StatusHandler#process` resolves commits by `sha` alone and creates a passing `Status` regardless of which org's secret authenticated the request, affecting `victim-org/victim-repo`'s stack.

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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
