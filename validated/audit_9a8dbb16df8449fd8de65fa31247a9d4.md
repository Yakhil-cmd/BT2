## Title
Webhook signature verification is keyed to `repository.owner.login` while the `PullRequest` lookup is keyed to `repository.full_name`, allowing a mismatched-owner payload to overwrite an unrelated organization's PR - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` used for HMAC verification from `params.dig('repository','owner','login')`, but `PullRequest::AssignedHandler#pull_request` resolves the target repository/PR from the independent `params.repository.full_name` field. These two fields are never cross-checked, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever the selected organization has no `webhook_secret` configured.

### Finding Description
The binding the question asserts should hold is: `organization derived from repository.owner.login (used for HMAC verification)` == `organization owning the repository named in repository.full_name (used for the PullRequest lookup)`. Tracing the code shows this equality is **not enforced anywhere**.

- `WebhooksController#verify_signature` picks the app via `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` when that organization's `webhook_secret` is blank: `return true unless webhook_secret` [3](#0-2) . The test fixture `secrets_double_github_app.yml` shows this is a real, supported configuration shape (multiple organizations, each independently configured, some with `webhook_secret: # nil`) [4](#0-3) .
- `AssignedHandler#process` then resolves the target `repository` and `pull_request` purely from `params.repository.full_name` and `params.number`, with no reference back to `repository.owner.login` used during verification: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and the `find_by(number:, stacks: { repositories: { id: repository.id } })` lookup [5](#0-4) , followed by `pull_request.update(github_pull_request: params.pull_request)` [6](#0-5) .

Exploit flow: the attacker crafts a `pull_request` webhook payload where `repository.owner.login` names any Shipit-configured organization that has no `webhook_secret` set (a legitimate, documented configuration state per `docs/setup.md`/`secrets_double_github_app.yml`), while `repository.full_name` names a *different*, victim organization's repository, with `number` matching a real PR in that victim's stack, and `pull_request.head.sha`/`head.ref` set to attacker-chosen values, and `action` = `"assigned"`. `verify_signature` looks up the secret-less org's `GitHubApp`, calls `verify_webhook_signature`, which returns `true` unconditionally without inspecting `X-Hub-Signature` at all. The request then reaches `AssignedHandler#process`, which loads and overwrites the victim PR's `github_pull_request` JSON using the attacker's payload.

Existing guards do not close this gap: `drop_unhandled_event` only checks the event name exists a handler for, not payload consistency; the `ExplicitParameters` schema in the handler only validates types/presence, not that `repository.owner.login == repository.full_name`'s owner; `check_if_ping` is irrelevant; there is no `Repository`/`Stack` validation cross-checking the verifying organization against the target repository.

### Impact Explanation
A successful forged request lets an attacker mutate `github_pull_request` (including `head.sha`/`head.ref`) on a `PullRequest` belonging to a stack/repository owned by an organization other than the one whose (missing) secret was used to "verify" the request. `head.sha`/`head.ref` on `PullRequest` records feed downstream commit/deploy resolution logic, so this is a cross-tenant write into another organization's PR metadata, matching the Critical category "a payload for one repository mutating another's stack/commit". This is repeatable against any PR number/repo as long as at least one configured organization in the Shipit instance has no `webhook_secret`.

### Likelihood Explanation
The precondition is that the Shipit deployment has at least one configured GitHub organization/app entry with `webhook_secret` unset — a state explicitly supported by the config format and exercised in test fixtures (`secrets_double_github_app.yml`), and plausible for smaller/internal-only orgs that operators assume don't need HMAC protection. Given that precondition, the attacker needs no credentials, sessions, or knowledge of any real secret — only knowledge of that org's login name (which is public) and the victim repo's `full_name`/PR number (also public). This makes the attack cheap and fully repeatable once the precondition holds; it does not require compromising the victim organization's own webhook secret at all.

### Recommendation
Enforce that the organization used for signature verification actually owns the repository named in the payload before dispatching to handlers — e.g., derive `repository_owner` strictly from the domain-parsed prefix of `repository.full_name` (not a separate `owner.login`/`organization.login` field), and reject payloads where they diverge. Additionally, treat a missing/blank `webhook_secret` as "verification unavailable" rather than "verification passes," e.g. require explicit opt-in (`allow_unsigned: true`) per organization instead of silently returning `true`.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb`-style setup (not adding to `test/**` here per audit rules, but describing the exact assertions):
1. Configure two orgs in test secrets: `AttackerOrg` (no `webhook_secret`) and `VictimOrg` (with `webhook_secret` set), each with a `Repository`/`Stack`.
2. Create `victim_pull_request = Shipit::PullRequest.create!(number: 7, stack: victim_stack, github_pull_request: { 'head' => { 'sha' => 'original_sha', 'ref' => 'main' } })`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, body:
```json
{
  "action": "assigned",
  "number": 7,
  "pull_request": { "id":1, "number":7, "url":"u", "title":"t", "state":"open",
    "additions":1, "deletions":1,
    "head": { "sha": "attacker_sha", "ref": "attacker_ref" },
    "user": {"login":"attacker"}, "assignees": [{"login":"attacker"}], "labels": [] },
  "repository": { "owner": { "login": "AttackerOrg" }, "full_name": "VictimOrg/victim-repo" },
  "sender": { "login": "attacker" }
}
```
   No `X-Hub-Signature` header is sent (or an arbitrary bogus one).
4. Assert `response` is `:ok` (verification passed because `AttackerOrg` has no secret).
5. Assert `victim_pull_request.reload.github_pull_request['head']['sha'] == 'attacker_sha'` — i.e., before the request it is `'original_sha'` and after the request it becomes the attacker-chosen value, despite the HMAC having been "verified" against `AttackerOrg`, not `VictimOrg`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L53-69)
```ruby
          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```
