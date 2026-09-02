### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while all event handlers dispatch on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, computed from `params.dig('repository','owner','login')` or `params.dig('organization','login')`. However, every webhook handler (`Shipit::Webhooks::Handlers::Handler#repository_name`) resolves the target repository/stack using a completely different JSON field, `payload.dig('repository', 'full_name')`. Nothing binds these two fields together, so the field the signature check authorizes against is not the field the write path acts on — the same class of bug as the `Buffer.sol` issue, where the resize check used `buf.buf.length` while the actual capacity term used elsewhere was `buf.capacity`.

### Finding Description [1](#0-0) 

`verify_signature` picks the GitHub App/org config with:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and verifies the raw HMAC body against that org's `webhook_secret` via `Shipit.github(organization: repository_owner).verify_webhook_signature`.

But `Handler#repository_name` (used by `PushHandler`, `StatusHandler`, pull-request handlers, etc.) resolves the acted-upon repository from: [2](#0-1) 
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
```
which is fed into `Repository.from_github_repo_name` [3](#0-2)  to find the `Stack` to sync.

In this engine's own multi-organization configuration model (documented at `test/dummy/config/secrets_double_github_app.yml` [4](#0-3) ), distinct organizations each have their own GitHub App and independent `webhook_secret`. An operator/admin of one configured organization ("OrgA") legitimately knows OrgA's `webhook_secret`. They can craft an arbitrary JSON payload where:
- `repository.owner.login` = `"OrgA"` (so `verify_signature` picks OrgA's app/secret, which the attacker can compute a valid HMAC for), and
- `repository.full_name` = `"OrgB/victim-repo"` (a repository belonging to a different, unrelated organization also configured on the same Shipit instance).

Because the raw-body HMAC only proves "this byte string was signed with OrgA's secret" — it says nothing about internal consistency between `repository.owner.login` and `repository.full_name` — `verify_signature` passes, and `PushHandler#process` [5](#0-4)  then looks up and mutates OrgB's `Stack` via `Repository.from_github_repo_name(repository_name)&.stacks`.

This is precisely the "organization that authenticated versus the repository that is written" trust-binding break called out in scope: the equality `organization_verifying_signature == organization_owning_written_repository` does not hold and is never checked.

### Impact Explanation
An attacker who administers any one organization configured in this Shipit instance's `github:` secrets (a legitimate, unprivileged-with-respect-to-other-orgs actor) can forge push/status/check-suite webhook deliveries that are attributed to and processed against a different organization's repository/stack, without ever having credentials, GitHub App installation, or write access to that other repository. Concretely for the `push` event, this triggers `GithubSyncJob` against another org's `Stack` with an attacker-chosen `expected_head_sha`, feeding attacker-influenced parameters into the stack's sync path. This crosses a repository/organization trust boundary that the signature check was supposed to enforce, matching the in-scope "cross-repository writes" impact category.

### Likelihood Explanation
Requires the deployment to configure more than one organization/GitHub App (a supported, documented configuration pattern in this engine — see `test/dummy/config/secrets_double_github_app.yml` and `docs/setup.md`), and requires the attacker to control (as an org owner) one of the configured organizations while targeting another. No Shipit session, API token, or webhook secret compromise of the victim org is needed — only the attacker's own, legitimately-known secret for their own org. Likelihood is moderate: it applies specifically to multi-tenant Shipit deployments, which the engine explicitly supports and documents.

### Recommendation
Bind the field used for signature-organization selection to the field used for repository resolution: derive the org used for both signature verification and downstream repository/stack lookup from a single canonical value (e.g., always parse `repository.full_name` and verify the split owner against the org selected for the secret, or normalize `Handler#repository_name` to reuse the exact `repository_owner` value/org validated during signature verification), rejecting the payload if `repository.owner.login` does not match the owner segment of `repository.full_name`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `test/dummy/config/secrets_double_github_app.yml`).
2. As the (unprivileged w.r.t. OrgB) administrator of `OrgA`, compute a valid `X-Hub-Signature` HMAC-SHA1 over a crafted JSON body using OrgA's known `webhook_secret`:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. `POST /webhooks` with header `X-Github-Event: push` and the computed signature.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, validates the signature against OrgA's secret, and passes.
5. `PushHandler#process` resolves the target via `repository.full_name` = `"OrgB/victim-repo"`, finds `OrgB`'s `Stack`, and enqueues `GithubSyncJob` for it — despite the request having been authenticated only against `OrgA`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
