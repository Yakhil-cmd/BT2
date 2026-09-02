### Title
Webhook signature verification is keyed off attacker-controlled payload fields, allowing cross-organization webhook forgery when a GitHub App's webhook secret is shared across installations - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to verify the `X-Hub-Signature` against by reading the `repository.owner.login` (or `organization.login`) field directly out of the untrusted, unsigned-until-verified JSON body, rather than from any property tied to the actual delivering GitHub App installation. Because a single GitHub App has exactly one webhook secret that is shared by every organization/repository it is installed on, Shipit's own documented multi-tenant configuration pattern (one `webhook_secret` value duplicated per org entry in `secrets.yml`, one physical App installed across many orgs) means the "organization that authenticated" the signature and "the repository that is written" by the handler are only ever the same value because the attacker chooses both. An attacker who legitimately receives (or can reproduce) a valid signature for their own org's installation can reuse that same secret to sign a forged payload whose `repository`/`organization` fields name a completely different, victim organization/stack hosted on the same Shipit instance.

### Finding Description
`verify_signature` picks the app config purely from payload content: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
```

`repository_owner` is derived entirely from the JSON body itself, before any cryptographic check has occurred: [2](#0-1) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` then loads the `GitHubApp` config for that named organization out of `secrets.github`, and `verify_webhook_signature` simply HMACs the raw body with whatever `webhook_secret` is configured for that organization entry: [3](#0-2) [4](#0-3) 

Shipit's own setup documentation and test fixtures describe the standard multi-org deployment as one `github:` block per organization, each with its own `webhook_secret` entry: [5](#0-4) [6](#0-5) 

However, a GitHub App's webhook secret is set once, at the App level, in the App's GitHub settings — it is not per-installation. If the same GitHub App is installed on multiple organizations (a common SaaS/multi-tenant Shipit deployment), every one of those organizations' entries in `secrets.yml` will legitimately carry the identical `webhook_secret` value, because that is the only secret GitHub actually gives the App owner. Consequently:
- `verify_webhook_signature` only proves "the sender knows *a* secret that matches *some* org name in the payload" — it proves nothing about which installation actually generated the delivery.
- The equality the code implicitly assumes but never checks is: `organization whose secret validated the signature == organization actually sending the webhook`. In the shared-secret deployment topology, this equality does not hold; any org sharing the App's secret can impersonate any other org sharing that same secret simply by changing `repository.owner.login`/`organization.login` in the payload.

Once signature verification "passes" (because the attacker computed a valid HMAC using the shared secret), the same attacker-controlled `repository` object is trusted by the downstream handlers to select and mutate a victim stack. For example, `PushHandler` locates victim stacks purely from the forged branch/repository scoping and calls `sync_github`, which can advance the stack's known head commit and, on a continuous-deployment-enabled stack, drive an actual deploy of an attacker-chosen SHA: [7](#0-6) 

`StatusHandler` similarly writes forged CI status entries onto real commits by SHA, which can be used to satisfy `ci.require` gates and unlock deploys/merges that a legitimate CI system never approved: [8](#0-7) 

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written": webhook authentication is meant to prove that GitHub, for a specific organization's installation, actually sent this payload; instead it only proves knowledge of a secret that, in the documented multi-org topology, is shared across every org using the same App. An attacker controlling (or with legitimate low-privilege access to) one tenant org on a shared Shipit instance can forge `push`/`status` webhooks that are accepted as authentic for a completely different tenant's repository/stack, enabling forged CI status writes and stack head advancement that can lead to an unauthorized deploy of attacker-chosen code — matching the Critical "unauthorized deploy" impact category.

### Likelihood Explanation
This requires the operator to run a genuinely multi-tenant Shipit instance where a single GitHub App is installed on more than one organization (the exact pattern Shipit's own docs and fixtures illustrate), and requires the attacker to be a member/admin of at least one of those installed organizations (an otherwise unprivileged actor with respect to the victim org). Given that GitHub Apps are inherently single-secret regardless of installation count, this is not a misconfiguration edge case but the expected outcome of following the documented "Using Multiple Github Applications" setup whenever the same App entity is reused. No `ApiClient` token, GitHub App private key, or repository write access to the victim's repo is needed — only the ability to receive (or independently compute) one valid webhook signature from the shared secret.

### Recommendation
Do not select the signing secret to verify against using data taken from the unverified payload. Instead:
- Verify the signature against every configured organization's secret (or a single canonical/global secret) before trusting any organization-identifying field in the body, or
- After verifying with a secret, cross-check that the `repository`/`organization` named in the payload is actually associated with the same GitHub App installation the request claims to originate from (e.g., via `installation.id` supplied by GitHub, compared against the configured `installation_id` for that org) rather than trusting the free-text `login` field alone.
- If one GitHub App is intentionally shared by multiple organizations, treat all of those organizations as one trust domain for the purposes of webhook authentication, and additionally validate that the `repository` full name in the payload actually belongs to a `Repository`/`Stack` legitimately associated with an org that installs that specific App/installation ID.

### Proof of Concept
1. Deploy Shipit configured for two tenant orgs, `OrgA` and `OrgB`, both installations of the same GitHub App (as shown in `docs/setup.md`'s "Using Multiple Github Applications" section) — both `secrets.yml` entries therefore carry the identical `webhook_secret` (this is a GitHub App-level, not installation-level, secret).
2. Attacker is a member of `OrgA` and has a real repo there wired to Shipit; they observe/derive one legitimate `X-Hub-Signature` HMAC for a payload signed with the shared secret (or simply compute the HMAC directly since they know the shared secret value that was distributed to them as part of App setup).
3. Attacker crafts a forged `push` payload: `{"ref": "refs/heads/main", "after": "<attacker-chosen-sha>", "repository": {"owner": {"login": "OrgB"}, "name": "victim-repo", "full_name": "OrgB/victim-repo"}}` and signs it with the shared secret.
4. `POST /webhooks` with `X-Github-Event: push` and the computed `X-Hub-Signature`.
5. `WebhooksController#verify_signature` computes `repository_owner == "OrgB"`, loads `Shipit.github(organization: "OrgB")`, and `verify_webhook_signature` succeeds because the secret is shared, despite the request never originating from GitHub's OrgB installation.
6. `PushHandler#process` runs against `OrgB`'s real stacks matching `branch == "main"`, calling `stack.sync_github(expected_head_sha: params.after)` with the attacker-chosen SHA, advancing/affecting a victim organization's stack state.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-45)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
