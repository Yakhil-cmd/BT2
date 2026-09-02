### Title
Webhook signature is verified against the `repository.owner.login` field, but every event handler acts on the independent `repository.full_name` field, allowing a valid signer for one organization to forge events for a stack under a different organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `params.dig('repository', 'owner', 'login')` (or `organization.login`), [1](#0-0) , and then verifies the raw body against that org's `webhook_secret` [2](#0-1) . Every actual event handler, however, resolves which `Repository`/`Stack` to act on using a *different* JSON field, `repository.full_name`, via `Handler#repository_name` / `#stacks` [3](#0-2)  and the equivalent `Repository.from_github_repo_name(params.repository.full_name)` calls used throughout the pull-request handlers [4](#0-3) .

### Finding Description
This is the exact analog of the audited bug class: two logically-related identifiers taken from the same message are supposed to refer to the same entity, but the verifier checks one while the executor acts on the other. In the original report, `_executeLiquidationCore` converts a token to the Chain A representation for sending, while `_handleLiquidationSuccess` uses that same field to look up state that only exists in Chain B's namespace — breaking the "same-entity" binding assumed by both fields.

Here, Shipit supports multiple configured GitHub Apps/organizations (see the multi-org secrets example, `test/dummy/config/secrets_double_github_app.yml`, where each org has its own independent `webhook_secret`) [5](#0-4) . The binding that must hold is:

`organization whose webhook_secret authenticated the request == organization that owns the repository the handler mutates`

`verify_signature` establishes trust in exactly one field, `repository.owner.login`:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
but nothing ties this to the `repository.full_name` value that every handler subsequently uses to look up the target `Stack`/`Repository`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end

def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
```
Because the HMAC signature only proves the payload came from *someone who knows the secret for the org named in `repository.owner.login`*, and the JSON body itself is entirely attacker-controlled once that secret is known, an attacker who legitimately installed the App on **their own** GitHub organization (and therefore legitimately knows their own org's `webhook_secret`, e.g. by reading it from their own installation configuration or from a leaked config for that specific org) can craft a webhook payload where:
- `repository.owner.login = "attacker-org"` (used only for picking/verifying the secret), and
- `repository.full_name = "victim-org/victim-repo"` (used by every handler to pick the actual `Stack`).

The controller will select `Shipit.github(organization: "attacker-org")`, verify the signature successfully (attacker signed with their own known secret), and then dispatch the event to handlers that operate on `victim-org/victim-repo`'s stacks — a repository the attacker's organization has no relationship to and no App installation on.

### Impact Explanation
Reachable handlers keyed only off `repository.full_name` include:
- `PushHandler`, which calls `stack.sync_github(expected_head_sha: ...)` for any not-archived stack on the matched branch [6](#0-5) , letting an attacker force syncs/spurious activity against a stack they don't own.
- `PullRequest::OpenedHandler`/`ClosedHandler`/`LabeledHandler`/etc., which create, archive, or unarchive Review Stacks and update `PullRequest`/`MergeRequest` state purely based on the forged `repository.full_name`/pull-request payload fields [7](#0-6) , [8](#0-7) .
- `MembershipHandler` (referenced in tests) creates/removes `Team`/`Membership` records keyed on the forged organization data, which can affect `Shipit.github_teams` authorization checks used by `Authentication#force_github_authentication`.

Corrupting merge/review-stack state or team membership feeds into Shipit's own authorization and merge-queue automation, matching the "escalation into `Shipit.github_teams` authorization" / unauthorized-state-mutation class of High-severity impact defined in scope.

### Likelihood Explanation
Exploitation requires the operator to have configured Shipit with more than one GitHub App/organization (a documented, supported configuration — see `secrets_double_github_app.yml`), and requires the attacker to control (own an App installation on) at least one of those configured organizations, which is a normal, unprivileged position for an external contributor's own org — not a Shipit account, `ApiClient` token, or `webhook_secret` for the *victim* org. No repository write access to the victim repo, no privileged Shipit account, and no interception of victim secrets are needed, satisfying the "unprivileged attacker" constraint.

### Recommendation
In `WebhooksController#verify_signature`/`repository_owner`, and in every `Handler#stacks`/`repository_name` lookup, enforce that the organization used to select/verify the webhook secret is derived from (or cross-checked against) the same `repository.full_name` that handlers use to resolve the `Repository`/`Stack`. Concretely: parse the organization out of `repository.full_name` (`full_name.split('/').first`) instead of trusting the separate `repository.owner.login` field for secret selection, or explicitly assert `repository.owner.login == full_name.split('/').first` before dispatching to handlers, rejecting mismatches with a 422.

### Proof of Concept
1. Shipit is configured with two GitHub Apps: `AttackerOrg` (attacker legitimately installed the App and knows its `webhook_secret`) and `VictimOrg` (hosts `VictimOrg/victim-repo`, tracked as a Shipit `Stack`).
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "AttackerOrg" },
    "full_name": "VictimOrg/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(AttackerOrg_webhook_secret, body)>` and POSTs it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "AttackerOrg")` and successfully verifies the signature against the attacker's own secret [2](#0-1) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("VictimOrg/victim-repo")` [3](#0-2)  and triggers `stack.sync_github(expected_head_sha: ...)` for the victim's stack, despite the request never being signed by `VictimOrg`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-79)
```yaml
    OrgTwo:
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```
