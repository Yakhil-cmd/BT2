### Title
Webhook signature verified against organization derived from unvalidated payload field while handlers act on a different repository field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate a webhook against by reading `repository.owner.login` (falling back to `organization.login`) directly out of the attacker-supplied JSON body, before that body has been authenticated. The event handlers, however, act on `repository.full_name` (a *different* field of the same untrusted body) to decide which `Repository`/`Stack` to mutate. Because Shipit supports multiple GitHub organizations each with its own `webhook_secret` [1](#0-0) , nothing ties the organization whose secret validated the request to the repository that is ultimately written to.

### Finding Description
`Shipit.github(organization:)` resolves a distinct `GitHubApp` (and therefore a distinct `webhook_secret`) per organization via `github_app_config(organization)` [1](#0-0) . The webhook controller determines which organization to authenticate against purely from the request body itself:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`verify_webhook_signature` performs a standard HMAC comparison of the raw body against the secret for whatever organization `repository_owner` names [3](#0-2) . This is sound *only if* the field used to pick the secret (`repository.owner.login`) is guaranteed to correspond to the field the rest of the pipeline uses to decide what gets written. It is not: after `verify_signature` passes, `create` hands the entire parsed body to the matching event handler, e.g. `Shipit::Webhooks::Handlers::PushHandler`, `MembershipHandler`, `StatusHandler`, or the pull-request handlers, each of which resolves the target `Repository`/`Stack` from `repository.full_name` (or an equivalent full-name lookup), not from `repository.owner.login` [4](#0-3) . Since the entire JSON payload is author-controlled by whoever is submitting the HTTP request (the attacker crafts it, not GitHub), there is no requirement that `repository.owner.login` equal the owner segment of `repository.full_name`.

Concretely: Shipit operators can configure one Shipit instance to serve several GitHub organizations, each with its own GitHub App and `webhook_secret` [5](#0-4) . An actor who is a legitimate, unprivileged member/owner of Organization B (and therefore knows or can obtain Organization B's `webhook_secret`, e.g. by reading their own GitHub App settings) can build a payload where `repository.owner.login` is `"OrgB"` (so `verify_signature` selects and validates against Org B's secret) while `repository.full_name` is `"OrgA/some-repo"` — a repository that belongs to a different tenant they have no access to. The signature will verify successfully (it was computed with the correct secret for the org actually used for verification), yet the handler downstream will process the event as if it originated from `OrgA/some-repo`, writing to that repository's `Stack`/`Commit`/`MergeRequest` state.

This is exactly the "organization that authenticated versus the repository that is written" trust binding described by the report's bug class: the report's flaw was acting on data (collateral withdrawal) using a check bound to the wrong condition; here, the security decision (which secret authorizes the write) is bound to a field (`repository.owner.login`) that is disjoint from the field that determines what is actually written (`repository.full_name`), and the payload's internal consistency between those two fields is never validated.

### Impact Explanation
A successful exploit lets an attacker who controls webhook secrets for their own tenant/organization inject spoofed GitHub events (`push`, `pull_request`, `status`, `membership`, etc.) that are processed as if they came from an arbitrary *other* repository/organization hosted on the same Shipit instance. Depending on the handler this reaches, this can enqueue `GithubSyncJob`s, alter `MergeRequest`/`Commit` state, capture/alter PR labels used to drive provisioning decisions, or create/unarchive review stacks for a repository the attacker does not control — a cross-repository/cross-tenant write achieved without possessing that repository's actual webhook secret. This matches the required High/Critical impact category of unauthorized cross-repository writes.

### Likelihood Explanation
Likelihood is Medium: it requires a Shipit deployment configured for multiple GitHub organizations (the multi-org `github:` config keyed by organization, as documented) [6](#0-5) , and it requires the attacker to know one organization's `webhook_secret` — which is expected/available to anyone who owns/administers that organization's GitHub App, not a privileged Shipit credential. No Shipit session, `ApiClient` token, or GitHub write access to the *target* repository is needed, only knowledge of a webhook secret for a tenant the attacker legitimately controls.

### Recommendation
Do not let a payload field select the trust boundary (which secret to verify with) independently of the field that determines the effect (which repository is mutated). After signature verification succeeds for organization `O`, re-derive the acted-upon repository from `O` (or verify `repository.full_name`'s owner segment equals the organization that authenticated the signature) before dispatching to handlers, rejecting the event with 422 on mismatch.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own `webhook_secret` in `secrets.github` per the documented multi-org schema.
2. As a member of `orgB` (attacker), obtain `orgB`'s `webhook_secret` (available to `orgB`'s own GitHub App administrators).
3. Craft a `push` webhook JSON body where `repository.owner.login = "orgB"` but `repository.full_name = "orgA/target-repo"` (and `ref`/`after` pointing at attacker-chosen values).
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgB_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#repository_owner` resolves `"orgB"`, `verify_signature` validates successfully against `orgB`'s secret [7](#0-6) .
6. `Shipit::Webhooks.for_event('push')` handler processes the body using `repository.full_name`, causing Shipit to sync/act on `orgA/target-repo` even though the attacker never possessed `orgA`'s webhook secret.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

**File:** docs/setup.md (L61-105)
```markdown

```yaml
production:
  secret_key_base: some-long-string
  host: example.com
  redis_url: "redis://redis-host"
  github:
    app_id: 42
    installation_id: 43
    bot_login: "my-app[bot]"
    webhook_secret: some-secret-value
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
    domain: # The domain name of your GitHub Enterprise instance, leave it empty if you use github.com
```
```
