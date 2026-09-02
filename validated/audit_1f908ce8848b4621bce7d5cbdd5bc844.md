This confirms the multi-tenant configuration is a documented, supported feature. This is the key finding: Shipit supports multiple GitHub Apps, one per organization, each with its own `webhook_secret`, configured under `secrets.github.<organization>` as documented in `docs/setup.md` and `config/secrets.development.shopify.yml`. The `WebhooksController#verify_signature` selects which app's `webhook_secret` to check against based solely on `repository_owner`, extracted from the payload's `repository.owner.login` (or `organization.login`), while the `Handler` base class (and subclasses like `PushHandler`) resolve which repository/stack to write to based on `repository.full_name` — a separate field within the same JSON body.## Title
Cross-organization write via mismatched webhook signature scope and repository resolution field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to verify a webhook's HMAC signature against using `repository_owner`, a value read from the payload's `repository.owner.login` (falling back to `organization.login`). But once the signature check passes, every `Shipit::Webhooks::Handlers::Handler` subclass resolves the actual repository/stack to mutate using a *different* field from the same payload: `repository.full_name`, via `Repository.from_github_repo_name(repository_name)` [1](#0-0) . In Shipit's documented multi-tenant configuration, each GitHub organization has its own independent `webhook_secret` [2](#0-1) [3](#0-2) . Nothing ties `repository.owner.login` (the field the signature check trusts) to `repository.full_name` (the field the handlers trust), so a payload signed with Org A's webhook secret can carry a `repository.full_name` pointing at Org B's repository.

### Finding Description
`verify_signature` computes the HMAC over the full raw body, but decides *which* secret to check it against using only `repository_owner`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

After the signature is accepted, `create` dispatches the raw parsed JSON to handlers unchanged [5](#0-4) . Every handler (`PushHandler`, `StatusHandler`, pull-request handlers, etc.) locates the target `Repository`/`Stack`/`Commit` using `repository.full_name`, not `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

`StatusHandler` doesn't even use `repository` at all for scoping — it updates statuses solely by commit SHA across the whole install [7](#0-6) , and `PushHandler` triggers a GitHub sync for any stack under the resolved repository [8](#0-7) .

Shipit explicitly supports one GitHub App/webhook secret *per organization* for multi-tenant installs, configured under `secrets.github.<organization>` [2](#0-1) , resolved via `Shipit.github_app_config` / `Shipit.github` [9](#0-8) . An organization admin who legitimately owns the webhook secret for their own org (Org A) — because they configured it in their own repo's/org's GitHub App webhook settings, matching what the Shipit admin put in `secrets.github.OrgA.webhook_secret` — can therefore sign an arbitrary JSON body themselves. Because `verify_signature` only checks that `repository.owner.login == "OrgA"` matches the secret used, they can freely set `repository.full_name` to `"OrgB/target-repo"` inside that same signed body. The equality the code is implicitly assuming — `repository.owner.login == repository.full_name.split('/').first` — is never enforced, and is exactly the trust binding described in the prompt: *"an organization that authenticated versus the repository that is written."*

### Impact Explanation
This allows an attacker who controls (or is a legitimate integrator for) one tenant organization in a multi-org Shipit deployment to forge webhook events that are attributed to and acted upon a different organization's repository/stack, without possessing that organization's secret. Depending on handler, this can:
- Trigger `GithubSyncJob`/`stack.sync_github` on Org B's stacks (`PushHandler`), causing Shipit to pull and act on refs it wouldn't otherwise sync from, potentially feeding into continuous-deployment pipelines.
- Inject arbitrary commit statuses (`StatusHandler`) against any commit SHA in the system, since it isn't repository-scoped at all, which can flip CI-gating (`ci.require`) checks that gate automated deploys.
- Manipulate PR/team/membership state cross-tenant, feeding into Shipit's own authorization/state model.

This crosses the "cross-repository writes" / "unauthorized deploy" impact bar called out in the rules, since it lets an actor authenticated for one org's webhook cause writes/deploy-triggering actions scoped to a different org's repository.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured for multiple GitHub organizations (a documented, first-class configuration, not a misconfiguration) [2](#0-1) , and (2) the attacker being a legitimate holder of one tenant org's webhook secret (e.g., an org admin who set up the GitHub App webhook for their own org). No privileged Shipit session, `ApiClient` token, or GitHub App private key is needed — only knowledge of one org's `webhook_secret`, which by design is available to whoever configures that org's webhook on the GitHub side. This is a realistic, low-effort attack for exactly the multi-tenant use case Shipit ships support for.

### Recommendation
In `WebhooksController#verify_signature`, after confirming the HMAC is valid for the app selected by `repository_owner`, also assert that `repository.full_name`'s owner segment equals `repository_owner` (or, more robustly, that the whole `repository.full_name`/`repository.id` is consistent with the organization whose secret validated the signature) before dispatching to handlers. Alternatively, resolve the target `Repository` first, derive the organization strictly from the stored `Repository#owner`, and verify the signature using that organization's app rather than trusting the unauthenticated payload's owner field for secret selection.

### Proof of Concept
1. Deploy Shipit with two GitHub Apps configured, e.g. `secrets.github.OrgA.webhook_secret = "secretA"` and `secrets.github.OrgB.webhook_secret = "secretB"`, following the documented multi-org setup [2](#0-1) . Assume Shipit tracks a `Repository` `OrgB/private-repo` with a stack.
2. As an operator with legitimate access to Org A's webhook configuration (knows `secretA`), craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/private-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, loads Org A's `GitHubApp`, and successfully verifies the signature against `secretA` [10](#0-9) .
5. `create` dispatches the parsed body to `PushHandler`, which resolves `repository_name = "OrgB/private-repo"` [11](#0-10)  and calls `stack.sync_github(expected_head_sha: ...)` on Org B's stack [8](#0-7)  — despite the request only ever proving knowledge of Org A's secret.

### Citations

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

**File:** docs/setup.md (L182-209)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-46)
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
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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
