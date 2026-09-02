### Title
Webhook signature verification is scoped to one organization while the acted-upon repository is read from an unauthenticated field, allowing unsigned webhooks to spoof stacks belonging to any other configured organization - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* organization's webhook secret to verify against using `repository_owner`, a value derived from the payload itself, then delegates the HMAC check to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` when that organization has no `webhook_secret` configured. Every webhook `Handler`, however, resolves the repository/stack to act on from a *different* payload field (`repository.full_name`) that is never bound to the "authenticated" organization. This breaks the equality `organization verified == repository acted upon`.

### Finding Description
`verify_signature` selects the GitHub App config to check against based on data in the untrusted request itself: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` bypasses HMAC validation entirely whenever the resolved organization has no `webhook_secret` configured: [3](#0-2) 

Shipit explicitly supports multiple GitHub organizations each with independent config (including independently optional `webhook_secret`), selected by the `Shipit.github_app_config(organization)` lookup keyed off organization login: [4](#0-3) [5](#0-4) 

Once `verify_signature` passes (or is bypassed), the actual event handler ignores the "authenticated" organization entirely and resolves the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')`: [6](#0-5) 

`PushHandler`, for example, uses that unauthenticated `full_name`-derived `stacks` scope to call `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived stack for the given branch: [7](#0-6) 

So the binding that should hold — *the organization whose secret verified the request* == *the organization/repository the handler is allowed to mutate* — does not hold. `repository_owner` (used only to pick the verification secret) and `repository.full_name` (used only to pick the mutated `Repository`/`Stack`) are two independent JSON paths in the same attacker-supplied body. Nothing forces them to refer to the same GitHub repository/organization, and the code path that permits skipping verification (`return true unless webhook_secret`) is a first-class, documented configuration option, not a mounting/deployment error by the host app.

### Impact Explanation
In any multi-organization Shipit deployment where at least one configured organization has no `webhook_secret` set, an attacker who only needs to know that organization's login (visible via the GitHub App's public listing/installations) can send a completely unsigned POST to `/webhooks` with:
- `organization.login` (or `repository.owner.login`) = the org with no secret, satisfying `repository_owner` and passing (bypassed) verification, and
- `repository.full_name` = `"victim-org/victim-repo"` for a *different*, properly secured organization's repository.

This forged, unauthenticated request is then processed as a legitimate `push` webhook against the victim repository's stacks, triggering `Stack#sync_github` with an attacker-chosen `expected_head_sha`, and can similarly drive `PullRequest` handlers to create/archive/unarchive `ReviewStack`s or capture labels for arbitrary repositories. This crosses a repository/organization trust boundary without any credential belonging to that organization, matching the "unauthorized deploy" / cross-repository-write class of impact.

### Likelihood Explanation
Exploitability depends on the deployment actually configuring at least one organization without a `webhook_secret` — a state the codebase explicitly supports and documents (see the double-app fixture) rather than a misconfiguration prohibited by the engine. Any operator running Shipit for multiple organizations, where one is added for testing/local development without a secret, exposes every other organization's stacks to spoofed webhooks. This does not require holding any `ApiClient` token, `webhook_secret`, or GitHub App private key for the *targeted* organization — only knowledge of an unrelated organization's login that happens to be under-configured.

### Recommendation
- Never allow "no secret configured" to translate into "verification bypassed"; require an explicit, deployment-wide opt-out flag instead of `return true unless webhook_secret`.
- Bind the handler's repository resolution to the same organization that was authenticated in `verify_signature`, e.g. pass the verified organization into `Handler.call` and assert `repository.full_name` starts with `"#{verified_organization}/"` before processing.
- Reject webhooks where `repository.owner.login`/`organization.login` and the owner segment of `repository.full_name` disagree.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `AttackerOrg` (no `webhook_secret`) and `VictimOrg` (has a `webhook_secret`, hosts stack `VictimOrg/app`).
2. POST to `/webhooks` with header `X-Github-Event: push` and no `X-Hub-Signature`, body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "organization": { "login": "AttackerOrg" },
  "repository": { "full_name": "VictimOrg/app" }
}
```
3. `repository_owner` resolves to `AttackerOrg` (`organization.login` fallback) → `verify_webhook_signature` short-circuits to `true` because `AttackerOrg` has no `webhook_secret`.
4. `PushHandler#process` resolves `stacks` from `repository.full_name = "VictimOrg/app"` and calls `sync_github(expected_head_sha: "<attacker-chosen sha>")` on `VictimOrg`'s stack, entirely bypassing that organization's own webhook secret protection.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
