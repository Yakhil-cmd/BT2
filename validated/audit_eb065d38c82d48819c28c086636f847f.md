### Title
Webhook signature verification is keyed on `repository.owner.login`, but every event handler dispatches on the independently-forgeable `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to HMAC-check the request against using `repository.owner.login` (or `organization.login`) read out of the **same JSON body** the attacker controls. Once that check passes, every `Shipit::Webhooks::Handlers::Handler` subclass instead resolves the target `Repository`/`Stack` from a *different* field of the same body, `repository.full_name`. Nothing ties these two fields together, so the "organization whose secret authenticated the request" and "the repository whose stacks get acted upon" are two separate, independently-controlled values inside one attacker-supplied payload.

### Finding Description
The signature check is:
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
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`verify_webhook_signature` explicitly treats an unconfigured secret as automatically verified:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

Every handler, however, ignores `repository.owner.login` entirely and instead resolves the target repository from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler` uses this to sync arbitrary tracked stacks:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 

and `PullRequest::OpenedHandler` similarly resolves the repository from `params.repository.full_name` independently of `repository.owner.login`:
```ruby
def repository
  @repository ||=
    Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
    Shipit::NullRepository.new
end
``` [5](#0-4) 

**The binding that should hold, but doesn't:** `organization authenticated by verify_signature (repository.owner.login) == organization that owns the repository whose stacks are mutated (repository.full_name)`. Because both values live in the same unsigned-until-verified JSON body, and GitHub itself always produces them consistently, this binding only holds for *genuine* GitHub deliveries. Once any organization configured in this Shipit instance has `webhook_secret` unset (`config/secrets.yml` explicitly documents this as a valid, optional setting) [6](#0-5)  or the test fixture setting `"webhook_secret": null` [7](#0-6) , `verify_webhook_signature` returns `true` unconditionally for that org, and the attacker can set `repository.owner.login` to that weakly-configured org while setting `repository.full_name` to `victim-org/victim-repo` for a completely different, fully-secured organization tracked by the same Shipit instance.

### Impact Explanation
An unprivileged, unauthenticated external attacker (no Shipit session, no GitHub token, no push access to the victim repository) can forge `push`, `pull_request`, `status`, or `check_suite` webhook deliveries against any stack tracked by the Shipit instance, as long as one other organization on the same instance has no webhook secret configured. This lets the attacker:
- Trigger `stack.sync_github` on arbitrary stacks via forged `push` events, forcing out-of-band GitHub syncs at attacker-chosen times.
- Force-create review stacks or manipulate pull-request-driven state machines via forged `pull_request` events pointed at a victim repository.
- Inject forged commit statuses via `StatusHandler`, which can influence merge-queue "all status checks passed" gating (`MergeRequest#any_status_checks_failed?` / `#all_status_checks_passed?`) [8](#0-7) , potentially contributing to an unauthorized merge/deploy decision for a repository the attacker has no access to.

This crosses the "cross-repository writes" / "unauthorized deploy" bar because the authentication boundary (per-organization webhook secret) is bypassed for repositories outside the weakly-configured organization.

### Likelihood Explanation
Requires only that the Shipit deployment tracks at least two GitHub organizations, one of which has no `webhook_secret` set — a state the project's own setup docs and test fixtures treat as a normal, supported configuration, not a misconfiguration to warn against. Given that, exploitation requires zero credentials: a single crafted HTTP POST with a mismatched `repository.owner.login` / `repository.full_name` pair.

### Recommendation
Bind the two fields together: after `verify_signature` succeeds, re-derive/require that `repository.full_name`'s owner segment matches the `repository_owner`/`organization.login` used to select the webhook secret (or, more robustly, always require a non-blank `webhook_secret` per organization and reject payloads where the two owner references diverge) before dispatching to any `Handler`.

### Proof of Concept
1. Configure a Shipit instance tracking two orgs: `weak-org` (no `webhook_secret`) and `victim-org` (webhook_secret set, tracks stack `victim-org/victim-repo`).
2. POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "weak-org" }, "full_name": "victim-org/victim-repo" }
}
```
No valid `X-Hub-Signature` is required because `Shipit.github(organization: "weak-org").verify_webhook_signature` returns `true` when `webhook_secret` is blank [2](#0-1) .
3. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: ...)` on its stacks [4](#0-3) , despite the request never being authenticated against `victim-org`'s secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** docs/setup.md (L107-119)
```markdown
**`secret_key_base`** Should be generated automatically by Rails. It is used for signing session cookies etc.

**`host`** Should specify the domain of your shipit instance, e.g. `shipit.example.com`.

**`redis_url`** Should point to a working Redis database.

**`github.app_id`** The GitHub App ID, it can be found under General > About

**`github.installation_id`** The ID of your GitHub App installation, it can be found under Organization Settings > Installed GitHub Apps > Configure. Then look at the URL it should follow this pattern: `https://github.com/organizations/<you-org>/settings/installations/<app-id>`.

**`github.bot_login`** The login of the App [bot] user. Every GitHub App have an associated `[bot]` user which acts as the author of the App actions through the API, for example when an App merges a Pull Request. It should be the App "slug" with the suffix `[bot]`. For example if your app settings URL is `https://github.com/organizations/ACME/settings/apps/acme-shipit/installations`, the bot user should be `acme-shipit[bot]`. If you are unsure, you can leave it empty.

**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```

**File:** test/dummy/config/secrets.test.json (L7-13)
```json
  "github": {
    "domain": null,
    "app_id": 42,
    "installation_id": 43,
    "bot_login": "shipit[bot]",
    "webhook_secret": null,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S\n73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG\nM0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv\nibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu\npQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s\nGu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1\nu0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM\nTZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b\nqicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og\nqRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI\nRsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b\ngg9PFCkCgYEA+7u8A0l0C ... (truncated)
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
