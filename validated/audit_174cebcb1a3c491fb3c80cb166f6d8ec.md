This confirms the vulnerability: the webhook signature verification key is selected using `repository.owner.login` (or `organization.login`) from the untrusted JSON body, while the actual Stack that gets mutated is looked up using a completely different field, `repository.full_name`, in `Handler#stacks` and `Handler#repository_name` [1](#0-0) . `WebhooksController#verify_signature` picks the HMAC secret via `Shipit.github(organization: repository_owner)`, where `repository_owner` reads `params.dig('repository','owner','login')` [2](#0-1) . In multi-organization mode, `Shipit.github_app_config(organization)` looks up a distinct `webhook_secret` per organization key [3](#0-2) .

### Title
Webhook signature verified against the wrong organization's secret allows cross-organization/cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-organization Shipit deployment, the webhook signature is validated using a secret selected from the attacker-controlled `repository.owner.login` (or `organization.login`) field of the JSON payload, but the Stack that is actually mutated by the event handler is selected using a *different* attacker-controlled field, `repository.full_name`. Nothing binds these two fields together, so an attacker who legitimately controls a repository/organization configured in Shipit (and therefore knows that organization's `webhook_secret`) can forge a payload whose `repository.owner.login` matches their own org (to pass signature verification) while `repository.full_name` points at a repository belonging to a different, victim organization also configured on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` selects the HMAC key like this: [4](#0-3) 

`repository_owner` is derived purely from the JSON body: [5](#0-4) 

For multi-org configurations, `Shipit.github(organization:)` resolves a per-organization `webhook_secret` from `secrets.github` keyed by that very same organization name: [3](#0-2) 
This is exactly the configuration shape documented and tested for multiple GitHub organizations sharing one Shipit instance [6](#0-5) [7](#0-6) .

Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, attacker-controlled JSON to a handler [8](#0-7) . All handlers (e.g. `PushHandler`) resolve the affected `Stack`/`Repository` from `repository.full_name`, a completely separate field from the one used for signature-key selection: [1](#0-0) [9](#0-8) 

Because `repository.owner.login` and `repository.full_name` are never cross-validated to refer to the same repository, the binding the system relies on — "the webhook secret that authenticated this payload belongs to the organization whose repository is being written" — is broken. This equality (`secret_org == repository_full_name's org`) is never checked.

### Impact Explanation
An attacker who operates a legitimate repository under Organization A (and therefore has access to configure/know Organization A's `webhook_secret`, e.g. by installing their own webhook forwarding for their own repo, or via any leaked/observed delivery) can forge an HMAC-valid webhook whose body claims `repository.owner.login: "OrganizationA"` but `repository.full_name: "OrganizationB/victim-repo"`. Handlers such as `PushHandler` will then call `stack.sync_github(expected_head_sha: params.after)` for the victim organization's stack using attacker-supplied `ref`/`after` values, and other handlers can archive/unarchive review stacks, update pull-request state, or otherwise mutate stacks belonging to a repository the attacker does not own. This is a cross-repository/cross-organization write achieved purely by crafting an inconsistent, self-signed payload — matching the required "cross-repository writes" Critical impact class.

### Likelihood Explanation
This only manifests when Shipit is configured with multiple GitHub organizations sharing per-org `webhook_secret`s (a documented, supported configuration) [6](#0-5) . The attacker must control at least one of the configured organizations' repositories (to know/derive its `webhook_secret`), which is a reasonably attainable position for a Shipit instance servicing multiple teams/orgs. No special privileges within Shipit itself, no session, and no `ApiClient` token are required — only the ability to send an HTTP POST to the public `/webhooks` endpoint with a correctly HMAC-signed but internally inconsistent body.

### Recommendation
Bind the field used to select the verification secret to the field used to resolve the Stack/Repository: derive both from `repository.full_name` (or otherwise verify that `repository.owner.login`/`organization.login` is consistent with `repository.full_name`'s owner) before selecting the `Shipit.github(organization:)` secret in `WebhooksController#verify_signature`, and reject the request if they diverge.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret`, as in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker controls a repo in `OrgA` and knows `OrgA`'s `webhook_secret` (e.g., from their own webhook delivery logs/settings).
3. Attacker crafts a push-event JSON body: `{"ref": "refs/heads/master", "after": "<attacker chosen sha>", "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo"}, ...}`.
4. Attacker computes `X-Hub-Signature` using `OrgA`'s known `webhook_secret` over this exact body and POSTs to `/webhooks`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")`, whose secret matches the attacker-supplied signature, so verification passes.
6. `PushHandler` resolves the stack from `repository.full_name` = `"OrgB/victim-repo"` and invokes `stack.sync_github(expected_head_sha: params.after)` against the victim organization's stack, despite the request being authenticated only for `OrgA`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-63)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
end
```
