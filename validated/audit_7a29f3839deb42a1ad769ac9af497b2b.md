### Title
Webhook signature verification binds to `repository.owner.login`, but stack lookup binds to `repository.full_name` — cross-organization webhook forgery in multi-org Shipit deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController` verifies the GitHub HMAC signature using the GitHub App configured for the organization named in `repository.owner.login` (or `organization.login`), but the webhook handlers that actually act on the payload resolve the target `Stack`/`Repository` using the independent `repository.full_name` field. In a multi-organization Shipit install, both fields are attacker-controlled parts of the same signed HTTP body, so an attacker who is legitimately a member of *one* configured GitHub organization (and thus knows that organization's real `webhook_secret`) can forge a validly-signed webhook whose `repository.full_name` names a stack belonging to a *different* configured organization, injecting fake `push`/`status`/`check_suite` events for a repository they don't control.

### Finding Description
`WebhooksController#verify_signature` determines which GitHub App/webhook secret to use for HMAC verification from `repository_owner`: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), and `Shipit.github(organization: repository_owner)` is looked up via `github_app_config`, which supports one `GitHubApp`/`webhook_secret` per organization when Shipit is configured for multiple GitHub organizations, as documented and fixtured: [3](#0-2) [4](#0-3) [5](#0-4) 

However, once the signature check passes, the payload is dispatched to handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and every handler resolves its target stacks through `Handler#stacks`/`Handler#repository_name`, which reads a *different* field, `repository.full_name`, not `repository.owner.login`: [6](#0-5) 

For example, `PushHandler#process` uses this `stacks` scope to enqueue `stack.sync_github(expected_head_sha: params.after)` for any stack matching the branch: [7](#0-6) [8](#0-7) 

The binding the code implicitly assumes is: `organization authenticated for HMAC (repository.owner.login) == organization that owns the repository acted upon (repository.full_name)`. Nothing in the controller or in `Handler` enforces this equality — both values are attacker-supplied fields of the same JSON body being validated by a single signature. An attacker who is an authorized member/admin of Organization A (one of the organizations configured in Shipit's `github:` multi-org section, and therefore in possession of Org A's real `webhook_secret`) can:

1. Craft a `push` (or `status`/`check_suite`) payload where `repository.owner.login = "OrgA"` (used only for signature verification) and `repository.full_name = "OrgB/victim-repo"` (used to resolve the actual `Stack`).
2. Sign the raw body with Org A's real webhook secret and set `X-Hub-Signature` accordingly — `verify_webhook_signature` passes.
3. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which looks up stacks for `OrgB/victim-repo` and calls `stack.sync_github(expected_head_sha: <attacker-chosen sha>)`, injecting a `GithubSyncJob` that fetches/appends the attacker-chosen commit into Org B's stack — with no relationship whatsoever between the attacker and Org B's GitHub organization or repository.

This directly parallels the reported bug class: an unauthenticated/unauthorized identifier in the payload (there, the archiver's public key to disconnect; here, `repository.full_name`) is acted upon even though only a different identifier in the same payload (there, none at all; here, `repository.owner.login`) is actually covered by the trust check.

### Impact Explanation
Because `GithubSyncJob` fetches commits via `stack.github_commits` (using the *victim* stack's own GitHub App credentials, not the attacker's), and because stacks with `continuous_deployment: true` automatically trigger `ContinuousDeliveryJob` → `trigger_continuous_delivery` → `trigger_deploy` once new commits/statuses are synced, this can result in an unauthorized deploy being triggered for a repository/organization the attacker does not control, purely by knowing another, unrelated organization's webhook secret. This matches the "unauthorized deploy" High/Critical impact criteria (cross-repository writes / unauthorized deploy).

### Likelihood Explanation
Exploitability requires Shipit to be configured with more than one GitHub organization (the documented "Using Multiple GitHub Applications" setup) and requires the attacker to be a legitimate member/admin of at least one of those organizations, which is a realistic scenario for shared internal Shipit instances that serve multiple teams/orgs. No token, session, or repository write access on the victim organization is needed — only knowledge of one configured org's `webhook_secret`, which per-org admins/members can obtain legitimately (e.g., by viewing their own GitHub App settings).

### Recommendation
After verifying the HMAC signature, re-derive the organization strictly from the same field the handlers use for repository/stack resolution (`repository.full_name`'s owner segment), and reject the webhook if it doesn't match the organization whose secret validated the signature — i.e., enforce `repository_owner == full_name.split('/').first` before dispatching to handlers, rather than trusting `repository.owner.login` and `repository.full_name` as independent, individually-uncorrelated fields.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications" section), and create a Stack for `OrgB/victim-repo` with `continuous_deployment: true`.
2. As a legitimate member of `OrgA` (with access to `OrgA`'s real webhook secret), build a `push` event payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-that-exists-on-OrgB/victim-repo>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Sign the raw JSON body with `OrgA`'s webhook secret (`sha1=` HMAC as computed in `GitHubApp#verify_webhook_signature`) and POST it to `/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<signature>`.
4. Observe that `WebhooksController#verify_signature` passes (Org A's secret validated), and `PushHandler` enqueues `GithubSyncJob` for the `OrgB/victim-repo` stack, potentially triggering an unauthorized continuous deployment.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-41)
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

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```
