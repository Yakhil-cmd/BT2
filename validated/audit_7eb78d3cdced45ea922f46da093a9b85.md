### Title
Webhook signature verified against an attacker-selected organization while the write target (`Commit` by SHA) is never scoped to that organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to HMAC-verify a webhook against based on a field read out of the *unverified* JSON body itself. In Shipit's documented multi-organization configuration, an attacker who legitimately controls one configured GitHub organization's webhook secret can forge a `status` webhook that is verified with *their own* org's secret, yet whose payload writes a `CommitStatus` onto a commit belonging to a completely different organization's stack, because `StatusHandler` does no repository/organization scoping at all.

### Finding Description
`verify_signature` picks the app/secret to check the signature against using: [1](#0-0) 

where `repository_owner` is derived straight from the JSON body: [2](#0-1) 

Shipit supports configuring one GitHub App (and one `webhook_secret`) per organization, documented and tested here: [3](#0-2) [4](#0-3) 

`Shipit.github(organization:)` resolves the config/secret purely from that string, with no other binding: [5](#0-4) 

The HMAC check itself only proves that *some* configured org's secret matches the raw body - it says nothing about which fields in that body are trustworthy relative to which org: [6](#0-5) 

Once the signature passes, `WebhooksController#create` dispatches the full JSON payload to handlers: [7](#0-6) 

For the `status` event, `StatusHandler#process` performs no repository or organization scoping whatsoever - it looks up commits globally by SHA across every stack in the installation: [8](#0-7) 

This is the exact bug-class analog from the report: two fields of the same attacker-influenced structure are compared/consumed inconsistently - one field (`repository.owner.login`/`organization.login`) picks *whose secret* validates the signature, while a completely different, unrelated value (`sha`, with no owner/org check) determines *what gets written*. The binding that should hold - "the organization whose secret validated this webhook == the organization owning the resource being mutated" - is never enforced. Because `sha` is a global namespace across all stacks/orgs tracked by the one Shipit instance, an attacker who is a legitimate admin of their *own* configured organization (and therefore legitimately knows *that org's* `webhook_secret` - not privileged access to Shipit or to the victim org) can sign a payload with their own secret while targeting a victim commit belonging to a different tenant's repository.

### Impact Explanation
A forged `status` event lets an unprivileged-relative-to-the-victim-org attacker inject an arbitrary commit status (`state`, `context`, `description`, `target_url`) onto any commit SHA tracked by any stack in the Shipit instance, not just their own organization's. Commit statuses are used to gate deploys via the `ci.require` mechanism (`Commit`/`Stack`/`Status::Group` — `app/models/shipit/commit.rb`, `app/models/shipit/stack.rb`), so a forged "success" status on a victim commit can be used to satisfy CI requirements and enable an unauthorized deploy on a stack the attacker has no legitimate relationship to - a cross-organization authorization bypass leading to an unauthorized deploy. `CheckSuiteHandler` and `PushHandler` are less directly exploitable (they trigger real GitHub-API-backed syncs rather than accepting arbitrary attacker data as truth), but `StatusHandler` accepts attacker-supplied state directly with zero binding check, making it the most severe instance of this class.

### Likelihood Explanation
Exploitability requires the deployment to use Shipit's multi-organization GitHub App feature (one `webhook_secret` per org) and for the attacker to control at least one of the configured organizations (e.g., they are an admin of one org that has installed the same Shipit GitHub App, or otherwise obtained that org's webhook secret) while targeting a commit SHA belonging to a different, victim organization also hosted on the same Shipit instance. This is a realistic misconfiguration/multi-tenant scenario that the "Using Multiple Github Applications" feature explicitly supports and documents, and requires no access to the victim's secrets, tokens, or Shipit session.

### Recommendation
Bind the signature-verifying organization to the resource being mutated: after selecting the webhook secret via `repository_owner`, re-derive the repository/stack strictly from the *same, already-authenticated* organization value rather than trusting `repository.full_name` or a bare `sha` lookup independently. `StatusHandler` in particular should scope its `Commit` lookup through `Repository`/`Stack` records that belong to the verified organization (mirroring what `Handler#stacks` already does for other handlers), rejecting statuses whose target commit's stack does not belong to the organization whose secret validated the request.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker-controlled) and `OrgB` (victim), per the multi-org `secrets.yml` schema.
2. Attacker, as an admin of `OrgA`, knows `OrgA`'s `webhook_secret` (legitimate for their own org).
3. Attacker crafts a `status` webhook payload:
   ```json
   {
     "sha": "<victim commit sha belonging to OrgB stack>",
     "state": "success",
     "context": "ci/required-check",
     "repository": { "owner": { "login": "OrgA" } }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/webhooks`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and validates successfully since the attacker used the correct secret for `OrgA`.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a `CommitStatus` on the victim's `OrgB` commit, with no check that the commit belongs to `OrgA`.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
