### Title
Webhook organization used for HMAC verification is not bound to the repository the payload actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization whose `webhook_secret` is used to validate `X-Hub-Signature` based on `repository.owner.login` (or `organization.login`) in the JSON body, while every event handler resolves the target `Stack`/`Repository` from a *different* field of the same body, `repository.full_name`. These two fields are never cross-checked against each other, so a valid signature only proves "this payload was signed with the secret of the organization named in `repository.owner.login`" — it does not prove the payload is authorized to act on the repository named in `repository.full_name`.

### Finding Description
`verify_signature` computes the signing organization purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` only recomputes the HMAC over the raw body using the secret configured for that resolved organization — it never inspects which repository the payload claims to describe: [3](#0-2) 

Every handler, however, resolves the `Stack`/`Repository` to act on using an entirely independent field, `repository.full_name`: [4](#0-3) 

Shipit explicitly supports hosting multiple GitHub Apps/organizations from a single instance, each with its own `webhook_secret`, as shown by the fixture used for multi-app configuration: [5](#0-4) 

The binding that should hold is:
`organization that authenticated the request (repository.owner.login → webhook_secret used)` == `repository the handlers act on (repository.full_name → Stack resolved)`

Because nothing enforces this equality, an attacker who legitimately possesses the `webhook_secret` for **one** configured organization (e.g., because they administer that org's GitHub App) can forge a payload where `repository.owner.login` names their own organization (so the signature check passes with their own secret) while `repository.full_name` names a repository belonging to a **different** organization configured on the same Shipit instance. The signature is valid, but the mutation lands on a stack the attacker does not control.

### Impact Explanation
Depending on the event type, this crosses a genuine trust boundary and lets an attacker who is authenticated only for their own organization's webhooks affect another organization's stacks:
- `push` event: `PushHandler#process` calls `stack.sync_github(expected_head_sha:)` for stacks matching the forged `full_name`/`branch`, which can trigger `GithubSyncJob` and, if continuous deployment is enabled on the target stack, an **unauthorized deploy** of a foreign repository/stack. [6](#0-5) 
- `status` event: `StatusHandler#process` writes a forged CI status onto commits of a foreign stack (`Commit.where(sha:)` is global, not scoped by the verified org), which can flip a commit from non-deployable to deployable and unblock/trigger deploys that rely on CI status gating. [7](#0-6) 
- `check_suite` event: similarly manipulates check-run refresh state for a foreign stack's commits. [8](#0-7) 

This matches the required impact category of an **unauthorized deploy** driven by a broken authentication/authorization binding, satisfying the High-severity criteria in the rules.

### Likelihood Explanation
Exploitation requires the attacker to already hold a valid `webhook_secret` for at least one organization configured on the Shipit instance — this is expected for a legitimate tenant/organization admin in a multi-org deployment, not a privileged Shipit account or `ApiClient` token, and not host-mounting misconfiguration (multi-org support is a first-class, tested feature per `secrets_double_github_app.yml`). Given that prerequisite, forging the JSON body (`repository.owner.login` vs `repository.full_name` mismatch) requires no further secrets, since HMAC covers the raw body which the attacker fully controls and can sign themselves with their own secret.

### Recommendation
In `WebhooksController#verify_signature` (or in `Webhooks::Handlers::Handler`), enforce that the organization used to select the `webhook_secret` matches the owner segment of `repository.full_name` (and of `organization.login` when present) before dispatching to handlers — reject the request if they differ. Alternatively, resolve the target `Stack`/`Repository` using `repository.owner.login` (the same field used for signature verification) rather than the independently-supplied `full_name`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` and `OrgTwo`, each with its own GitHub App and `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`), each managing at least one `Stack`.
2. As an administrator of `OrgOne`'s GitHub App, compute a valid `X-Hub-Signature` over a crafted JSON body using `OrgOne`'s `webhook_secret`:
   ```json
   {
     "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/target-repo" },
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>"
   }
   ```
3. POST this body with header `X-Github-Event: push` and the computed `X-Hub-Signature` to `/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"OrgOne"`, fetches `Shipit.github(organization: "OrgOne")`, and the signature verifies successfully.
5. `PushHandler#stacks` resolves the target repository via `payload.dig('repository', 'full_name')` = `"OrgTwo/target-repo"`, and `PushHandler#process` calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on `OrgTwo`'s stack — a stack the attacker never authenticated for — potentially triggering an unauthorized sync/deploy.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
