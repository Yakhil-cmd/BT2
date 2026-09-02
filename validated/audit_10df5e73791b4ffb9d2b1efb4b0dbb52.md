## Analysis

The bug-class hint ("payload field acted on but never covered by the verified signature" / "organization authenticated versus the repository written") maps cleanly onto the webhook authentication path in this engine.

`WebhooksController#verify_signature` selects **which GitHub App config (and therefore which `webhook_secret`) to use for HMAC verification** using a field taken directly from the untrusted, not-yet-verified JSON body: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

Shipit officially supports (and ships example config for) multiple GitHub organizations, each with its **own, independently optional** `webhook_secret`: [3](#0-2) [4](#0-3) 

`GitHubApp#verify_webhook_signature` explicitly treats a missing secret as "verification passes unconditionally":

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [5](#0-4) 

So the binding that is supposed to hold is:
`organization whose signature was verified == organization that owns the repository the handler acts on`

Once the request passes `verify_signature`, the raw JSON `params` are dispatched unchanged to handlers, several of which resolve the **target** repository/commit from a *different* field of the same payload — `repository.full_name` (via `Handler#repository_name`) — or, in the worst case, resolve **no repository scope at all**:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) 

`StatusHandler` is the most severe case: it looks up commits **globally by sha with no repository/stack scoping whatsoever**:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [7](#0-6) 

### Break of the binding

If any organization configured in `secrets.github` has `webhook_secret` left unset (an explicitly documented, supported configuration — see `docs/setup.md` "Webhook secret (optional)"), then:

1. An attacker crafts a POST to `/webhooks` with `repository.owner.login` set to that no-secret organization's login (a value the attacker can learn since it's just the org name), and an arbitrary `X-Hub-Signature` header (verification is skipped: `return true unless webhook_secret`).
2. `Shipit.github(organization: repository_owner)` resolves that org's `GitHubApp`, whose `verify_webhook_signature` returns `true` unconditionally — the request is now treated as "verified."
3. The attacker sets the `sha` (for a `status` event) to the SHA of an arbitrary commit belonging to **any other stack/repository/organization** managed by this Shipit instance, and sets `state: "success"`.
4. `StatusHandler` finds that commit purely by SHA — with **no repository ownership check tying it back to the organization that was "verified" in step 2** — and records a fabricated successful CI status on it.
5. Because `Commit#deployable?` and the merge-queue logic gate deploys/merges on `success?`, this forged status can make an otherwise-unverified/failing commit appear deployable/mergeable in a completely unrelated stack.

This directly breaks the required equality: the organization whose signature was accepted (the org with no secret) is never checked against the organization/repository the payload actually mutates (`params.sha`/`repository.full_name`), exactly mirroring the `PositionAction4626` pattern of "verified/authorized entity A, but action taken against unrelated entity B."

### Title
Webhook signature verification is keyed off an unauthenticated payload field decoupled from the repository/commit the handler mutates, allowing cross-organization forged commit statuses — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used to authenticate a webhook using `repository.owner.login` taken from the still-unverified JSON body. If any configured organization has no `webhook_secret` (a supported, documented configuration), signature verification for requests claiming that `owner.login` is bypassed entirely (`GitHubApp#verify_webhook_signature` returns `true` when `webhook_secret` is blank). Downstream handlers such as `StatusHandler` then act on a completely different, unauthenticated field of the same payload (`sha`) with no scoping back to the "verified" organization/repository, letting the forged request affect commits belonging to any other stack in the installation.

### Finding Description
- `WebhooksController#verify_signature` picks the verification key using `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:24-38,59-61`).
- `GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is not configured (`lib/shipit/github_app.rb:76-83`), and Shipit explicitly documents `webhook_secret` as optional per-organization (`docs/setup.md:30`, `test/dummy/config/secrets_double_github_app.yml`).
- Once "verified," the full untrusted `params` hash is handed to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (`app/controllers/shipit/webhooks_controller.rb:10-15`).
- `StatusHandler#process` resolves target commits purely by `params.sha`, globally, with no repository/organization scoping at all (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), and `Handler#stacks`/`#repository_name` in general resolve the target via `repository.full_name`, a field distinct from the `repository.owner.login` used for the authentication decision (`app/models/shipit/webhooks/handlers/handler.rb:32-38`).
- The two fields (`owner.login` used to select the verifying secret vs. `sha`/`full_name` used to select the mutated resource) are never cross-checked, so a request "authenticated" as belonging to a no-secret organization can still forge state for any other organization's commits/stacks.

### Impact Explanation
A forged `status` event can mark an arbitrary commit (in any stack managed by the Shipit instance, not just the "authenticated" org) as CI-successful. Since `Commit#deployable?` (`app/models/shipit/commit.rb`) and the merge-queue's `reject_unless_mergeable!`/status-check logic gate deploys and merges on commit status, this can be used to make a commit that never passed real CI appear deployable or mergeable, leading to an unauthorized deploy/merge — matching the "Critical: unauthorized deploy, rollback or merge" impact tier.

### Likelihood Explanation
Requires only that one organization among possibly several configured in `secrets.github` be set up without a `webhook_secret` — an explicitly supported/documented configuration (not a misconfiguration outside the documented deployment model). No repository write access, GitHub App private key, or session/API-client credentials are needed; the attacker only needs to know that organization's GitHub login and the target commit SHA of another stack.

### Recommendation
- Never allow `verify_webhook_signature` to return `true` when a secret is absent for a *multi-tenant* configuration; require a secret whenever more than one `github` organization key is configured, or require operators to opt in explicitly and loudly to unauthenticated mode.
- Bind the verified organization to the resource acted upon: after selecting `github_app` by `repository_owner`, re-derive/require that `repository.full_name`'s owner matches the same `repository_owner`, and have handlers scope lookups (especially `StatusHandler`) by the stack's own repository/organization instead of a global `Commit.where(sha:)` lookup.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `OrgA` (attacker-known, `webhook_secret` unset) and `OrgB` (victim, has an active stack/commit).
2. POST to `/webhooks` with header `X-Github-Event: status` and any `X-Hub-Signature` value, and body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/whatever" },
  "sha": "<sha of a commit belonging to a stack under OrgB>",
  "state": "success"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` regardless of the header.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the OrgB commit, and calls `create_status_from_github!`, recording a fabricated `success` status on it — usable to satisfy CI-gating for deploy/merge on OrgB's stack despite the attacker never having any credential or access related to OrgB.

### Citations

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
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
```

**File:** docs/setup.md (L20-30)
```markdown
## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
