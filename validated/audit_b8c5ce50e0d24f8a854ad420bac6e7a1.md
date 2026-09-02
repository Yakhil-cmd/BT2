### Title
Cross-organization webhook forgery via signature/payload binding mismatch in `WebhooksController` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to validate the request's HMAC against based on `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')`. The event handlers, however, resolve the target `Stack`/`Repository` using a *different* field of the same attacker-controlled JSON body: `payload.dig('repository', 'full_name')`. Because the HMAC only proves "this body was signed with organization X's secret", not "the `repository.full_name` field belongs to organization X", an operator of one legitimately onboarded GitHub organization can forge events for a repository belonging to a completely different organization on the same multi-org Shipit instance.

### Finding Description
`verify_signature` picks the app/secret to check against using the org derived from the payload: [1](#0-0) [2](#0-1) 

Multi-organization Shipit deployments are an explicitly documented, supported configuration where each organization has its own `webhook_secret`: [3](#0-2) [4](#0-3) 

Once the signature is accepted, the raw JSON body is dispatched to handlers, which look up the target repository/stack using a *different* field of the same JSON body — `repository.full_name` — via the shared `Handler` base class: [5](#0-4) 

For example `PushHandler` (which drives `Stack#sync_github`) and `CheckSuiteHandler` (which schedules check-run refresh) both key off `stacks`, which is derived from `repository.full_name`, not `repository.owner.login`: [6](#0-5) [7](#0-6) 

The `repository.owner.login` field used for authentication and `repository.full_name` field used for authorization/routing are independent JSON keys within one attacker-supplied body. GitHub itself would keep these consistent, but nothing prevents a forged direct POST to `/webhooks` from setting `repository.owner.login = "AttackerOrg"` (so the correct, known `webhook_secret` is picked and the HMAC validates) while setting `repository.full_name = "VictimOrg/victim-repo"` (so the handler acts on a stack belonging to an unrelated organization onboarded to the same Shipit instance).

This is the direct analog of the reported Pod bug class: the field that gates the trust decision (`repository_owner`, equivalent to the strictly-defined `measure`/`asset` tokens) is not the same field that the effectful operation acts on (`repository.full_name`, equivalent to the unconstrained per-mapping `TokenDrop`). The binding "organization that authenticated == repository that is written" is broken.

### Impact Explanation
An attacker who legitimately administers one GitHub organization/app onboarded to a shared, multi-organization Shipit instance (and therefore knows that organization's `webhook_secret`) can forge signed webhook events referencing `Stack`s that belong to a *different* onboarded organization they have no access to. Depending on handler:
- `push` → forged `Stack#sync_github(expected_head_sha:)` calls for a victim's stack (unauthorized state manipulation of a repository/organization the attacker does not control).
- `check_suite` → forced refresh of check runs for a victim's commits, which can influence merge-queue/deploy gating logic.
- `pull_request` events → forged archive/unarchive of victim review stacks.

This crosses the "cross-repository writes" / "unauthorized deploy" impact bar without any Shipit session, `ApiClient` token, or GitHub write access to the victim repository — only administrative control of one *other*, unrelated org configured on the same Shipit instance.

### Likelihood Explanation
Requires: (1) the Shipit instance configured for multiple GitHub organizations (a documented, supported setup — `test/dummy/config/secrets_double_github_app.yml` demonstrates it), and (2) the attacker controlling one of those organizations (i.e., knowing its `webhook_secret`, which they would legitimately possess as that org's own GitHub App owner). No other credential (no Shipit `ApiClient` token, no session, no victim GitHub credentials) is required — the `/webhooks` endpoint is unauthenticated aside from the HMAC check. This is realistic for any Shipit instance shared across multiple, mutually-untrusted organizations (e.g. a platform team hosting Shipit for several business units/orgs).

### Recommendation
Bind the signature-verification identity to the same field used for repository resolution: derive `repository_owner` from `repository.full_name`'s owner segment (or otherwise ensure the org used to select the `webhook_secret` is exactly the org prefix of `repository.full_name`), and reject the request if the two disagree. Alternatively, after selecting the `GitHubApp` for `repository_owner`, re-validate that any `repository.full_name`/`organization.login` referenced deeper in the payload belongs to that same verified organization before dispatching to handlers.

### Proof of Concept
Configure Shipit with two organizations, `AttackerOrg` (secret known to the attacker) and `VictimOrg` (a stack for `VictimOrg/victim-repo` exists in Shipit), per the documented multi-org config: [8](#0-7) 

1. Attacker builds a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "VictimOrg/victim-repo",
    "owner": { "login": "AttackerOrg" }
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(AttackerOrg_webhook_secret, raw_body)>` themselves, since they know `AttackerOrg`'s secret.
3. POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "AttackerOrg")` (from `repository.owner.login`) and validates successfully against the attacker-known secret. [1](#0-0) 
5. `Shipit::Webhooks.for_event("push")` dispatches to `PushHandler`, which resolves `stacks` via `repository.full_name = "VictimOrg/victim-repo"` and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack — an org the attacker never authenticated against. [9](#0-8)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
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
