### Title
Webhook payload fields used to resolve the target repository/stack are never bound to the organization whose secret authenticated the request, enabling cross-organization forged webhooks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on a payload field (`repository.owner.login`, with fallback to `organization.login`) that is itself part of the same JSON body being verified. [1](#0-0) [2](#0-1)  This only proves that the sender knows the secret configured for *that named organization* — it does not bind the rest of the payload (in particular `repository.full_name`, `pull_request`, `label`, etc., which the event handlers actually use to locate and mutate Stacks) to that same organization. In a multi-organization Shipit deployment, each org's owner can independently create/see their own GitHub App and its `webhook_secret`. [3](#0-2) [4](#0-3)  This is the same class of vulnerability as the reported `Controller.sol` bug: a value used to authorize an action (voting-power balance / here, the authenticating organization) can be decoupled from the value the action is actually performed against (the withdrawn amount / here, the target repository referenced elsewhere in the payload).

### Finding Description
- `verify_signature` computes `repository_owner` from the *unverified* JSON body (`params.dig('repository','owner','login') || params.dig('organization','login')`), and uses it to pick which `GitHubApp`/`webhook_secret` to check the signature against. [5](#0-4) 
- `Shipit.github(organization:)`, when the instance is configured for multiple organizations (documented, tested feature — see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`), looks up a *distinct* app config (and thus a distinct `webhook_secret`) per organization name supplied. [3](#0-2) [6](#0-5) 
- Once the signature check passes, the entire `params` hash — including fields that were never cross-checked against `repository_owner`, such as `repository.full_name` — is handed unmodified to every registered handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [7](#0-6) 
- Handlers such as the pull-request family (`opened_handler.rb`, `closed_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`, `label_capturing_handler.rb`) resolve the affected Stack using `repository.full_name` taken straight from that payload, per their declared `params` schema (`requires :repository do requires :full_name, String end`). [8](#0-7) 

Nothing in this pipeline verifies that the `full_name`'s owner segment equals the `repository_owner`/`organization.login` value that was actually used to select the secret that authenticated the request. Because the entire JSON body is attacker-authored before signing (an org owner signs whatever body they want with their own legitimate secret), an org admin who legitimately controls Org A's GitHub App can construct a payload where:
- `repository.owner.login` (or `organization.login`) = `"OrgA"` → passes signature verification with Org A's real secret.
- `repository.full_name` = `"OrgB/some-stack"` → causes handlers to resolve and mutate a Stack that belongs to a completely different, unrelated organization hosted on the same Shipit instance.

This is exactly the binding-equality break called out by the rules: *"an organization that authenticated versus the repository that is written."*

### Impact Explanation
On a Shipit instance configured to serve multiple GitHub organizations (an explicitly supported, documented configuration), this allows an attacker who is only an authorized user of one tenant organization to forge webhook events that mutate state belonging to a different tenant's stack — e.g., causing pull-request handlers to capture/replace labels, simulate PR opened/closed/merged transitions, or trigger review-stack lifecycle actions on a repository they have no legitimate access to. Because these actions influence merge-queue/CI gating state that downstream feeds into deploy/merge decisions, this is a cross-tenant, cross-repository write that breaks the multi-tenant isolation the per-organization `webhook_secret` design is meant to provide, which the rubric classifies as Critical ("cross-repository writes").

### Likelihood Explanation
Requires the attacker to be an owner/admin of at least one GitHub organization onboarded to a shared, multi-organization Shipit instance (i.e., they legitimately possess a `webhook_secret` for their own org) — this is an "unprivileged" position relative to any *other* tenant on that instance. No GitHub App private key, `ApiClient` token, or Shipit session is required; only the ability to send an arbitrary HTTP POST with a valid HMAC computed from their own org's known secret over an attacker-chosen JSON body.

### Recommendation
After signature verification, cross-check that every repository/organization identifier used later in the handler pipeline (e.g., `repository.full_name`'s owner segment, `pull_request.base.repo.owner.login`, etc.) is consistent with the `repository_owner` value that determined which secret was used to verify the signature. Reject (422) any payload where these values disagree, rather than trusting downstream handlers to independently and correctly scope every field back to the authenticated organization.

### Proof of Concept
1. Shipit is configured with `github: { OrgA: {...webhook_secret: "secretA"}, OrgB: {...webhook_secret: "secretB"} }` as documented in `docs/setup.md`. [4](#0-3) 
2. Attacker legitimately owns/administers OrgA's GitHub App and therefore knows `secretA`.
3. Attacker crafts a `pull_request` webhook JSON body where `repository.owner.login = "OrgA"` (so `WebhooksController#repository_owner` picks OrgA's app/secret) but `repository.full_name = "OrgB/victim-repo"`. [2](#0-1) 
4. Attacker computes `X-Hub-Signature` as `sha1=HMAC(secretA, raw_body)` and POSTs to `/github/webhooks`.
5. `verify_signature` succeeds because it validates against OrgA's secret using the org name embedded in the same payload. [1](#0-0) 
6. `LabelCapturingHandler`/other pull-request handlers process the payload using `repository.full_name = "OrgB/victim-repo"` to resolve and mutate OrgB's Stack, despite the request never having been authenticated on OrgB's behalf. [9](#0-8) 

**Caveat / uncertainty:** I was unable to fully read `app/models/shipit/webhooks/handlers/handler.rb` and `membership_handler.rb` in this session (tool errors on the final iteration) to confirm exactly how "stack" resolution from `full_name` is implemented and whether any additional owner-consistency check exists further down that I have not seen. If such a check exists elsewhere in the codebase, it would need to be verified directly (e.g., via a Devin session with full repository access) before treating this as fully confirmed exploitable end-to-end.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L8-48)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end

          def process
            return unless capture_labels?

            capture_labels

            stack
          end

```
