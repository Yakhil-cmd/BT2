### Title
Webhook Signature Verified Against `repository.owner.login` While Handlers Act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, the webhook signature check authenticates the payload against the GitHub App/secret belonging to the organization named in `repository.owner.login` (with signature verification silently skipped if that organization has no `webhook_secret` configured), while the event handlers that execute repository-scoped actions resolve the target `Repository`/`Stack` using the independent `repository.full_name` field from the same payload. An unauthenticated caller can therefore pick an organization with no configured `webhook_secret` to satisfy `verify_signature`, then point `repository.full_name` at a *different*, secret-protected organization's repository so the handler acts on a stack it was never authorized to reach.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to validate against using `repository_owner`, which is read straight from the untrusted JSON body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for that resolved organization — a state explicitly documented as optional (`webhook_secret: # nil`): [3](#0-2) [4](#0-3) 

Multi-org Shipit configurations exist precisely to host several independently-secured GitHub Apps/orgs side by side: [5](#0-4) [6](#0-5) 

Once `verify_signature` passes (bypassed because the chosen organization has no secret), `WebhooksController#create` dispatches the *entire, attacker-controlled* JSON body to the matching handler: [7](#0-6) 

Crucially, the handler base class resolves the actual target `Repository`/`Stack` from a **different** field of the same payload — `repository.full_name` — with no cross-check against the `repository.owner.login` value that was used for signature verification: [8](#0-7) [9](#0-8) 

`PushHandler#process`, for example, then invokes stack-level GitHub sync on whatever `Repository`/`Stack` was matched, using an attacker-supplied `expected_head_sha`: [10](#0-9) 

Because `repository_owner` (used for the security check) and `repository.full_name` (used for the actual action) are two independently attacker-controlled fields inside one JSON body, and because the whole endpoint is public with CSRF protection explicitly disabled: [11](#0-10) 
an attacker can satisfy authentication for an org with no secret while directing the handler's repository-scoped effects at a completely different, secret-protected org's stack. This is the "organization authenticated versus repository written" binding described in scope: the equality `organization_verified(payload) == organization_of(repository_acted_on(payload))` does not hold and is never checked.

### Impact Explanation
This lets an unauthenticated party (no Shipit session, no `ApiClient` token, no repository write access, no webhook secret for the targeted org) inject forged push/status/etc. webhook events against a stack belonging to an organization whose webhook is otherwise fully secured. Depending on the deployed instance's configuration, this can drive `GithubSyncJob` execution and commit/status ingestion for an arbitrary org's stack under attacker-chosen SHAs, which is the kind of cross-organization/cross-repository state-mutation the rules flag as High/Critical-adjacent (unauthorized action against a repository whose credential boundary the attacker never crossed).

### Likelihood Explanation
Requires only that the operator run a multi-organization Shipit configuration (a documented, supported setup) with at least one configured organization lacking a `webhook_secret` (also documented as optional/`nil`). No credentials, sessions, or GitHub App keys are needed by the attacker — only knowledge of a valid low-value/no-secret organization name and a target org's repository `full_name`, both discoverable from public GitHub metadata.

### Recommendation
After resolving `repository_owner` for signature verification, re-derive and enforce that the organization actually acted upon by the dispatched handler (i.e., the owner segment of `repository.full_name`, and `organization.login` for org-level events) matches the organization whose secret validated the request. Reject the webhook if these diverge, and stop treating a missing `webhook_secret` as an implicit "verified" state for organizations that coexist with other, secret-protected organizations in the same instance.

### Proof of Concept
1. Operate/target a multi-org Shipit instance configured with `OrgA` (no `webhook_secret` set) and `OrgB` (has `webhook_secret`, hosts a real stack such as `OrgB/prod-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and no/garbage `X-Hub-Signature`, body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/prod-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` and the request is accepted.
4. `PushHandler` resolves the target via `payload.dig('repository','full_name')` = `"OrgB/prod-repo"`, locates the real `OrgB` stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, all without ever presenting `OrgB`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-40)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
