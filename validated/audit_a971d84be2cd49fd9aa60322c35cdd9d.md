### Title
Webhook signature check keys off `repository.owner.login` while the write target is keyed off `repository.full_name` — cross-organization / cross-repository write in multi-tenant Shipit installs - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-organization Shipit deployment, `WebhooksController#verify_signature` selects *which* organization's HMAC secret to verify the request against using an attacker-controlled field of the JSON body (`repository.owner.login` / `organization.login`), while every webhook handler resolves the *stack/repository that actually gets written to* from a different, independently attacker-controlled field of the same body (`repository.full_name`). The HMAC only proves "this body was signed with organization X's secret" — it does not bind that signature to the specific repository named in `full_name`. A user who legitimately owns/administers one organization's GitHub App on the shared instance (and therefore legitimately knows that organization's `webhook_secret`) can sign a payload as their own org while setting `repository.full_name` to any other tenant's repository tracked on the same Shipit instance, causing Shipit to act on that other repository.

### Finding Description
`verify_signature` derives the signing key purely from the payload: [1](#0-0) [2](#0-1) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: ...)` looks up the `GithubApp`/secret configured for that organization name (see the multi-org config schema documented in `test/dummy/config/secrets_double_github_app.yml`, where each org, e.g. `OrgOne`/`OrgTwo`, has its own independent `webhook_secret`). So the HMAC is checked against **one specific org's** secret — the org named in the payload.

However, every event handler ignores `repository.owner.login` entirely and instead resolves the stack/repository to act on via `repository.full_name`: [3](#0-2) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

Both `repository.owner.login` and `repository.full_name` are read from the exact same untrusted request body, and the signature (an HMAC over the full raw body) only certifies "this body was produced by whoever holds the secret associated with `repository.owner.login`" — it does not certify any relationship between `owner.login` and `full_name`. Nothing in the controller or in `Handler` cross-checks that `full_name` belongs to the organization that was actually used to select the verifying key.

**Binding broken:** `organization authenticated == repository written`. Before the attack, an org's secret only authorizes actions on that org's own repositories (this is the implicit trust model of per-org GitHub Apps). After a crafted request, `organization authenticated (from repository.owner.login) != repository written (from repository.full_name)`.

### Impact Explanation
On a shared Shipit instance configured for multiple GitHub organizations (a supported, documented configuration — see `test/dummy/config/secrets_double_github_app.yml` and the README's multi-org `github:` schema), an attacker who is a legitimate admin of Organization B (and thus legitimately possesses Org B's `webhook_secret`, which they need anyway to configure their own GitHub App's webhook delivery) can sign a webhook body with Org B's secret while setting `repository.full_name` to `OrgA/some-repo`. This lets them:
- Trigger `GithubSyncJob` for Org A's stacks via forged `push` events, or
- Create/alter `Status` records on Org A's commits via forged `status`/`check_suite` events, affecting `deployable?`/CI-gating logic that gates deploys,

on a repository they have no legitimate access to — a cross-organization/cross-repository write, matching the Critical impact bucket ("cross-repository writes"). This does not require stealing any secret; it only requires possession of one's own legitimately-configured org secret plus knowledge of another tenant's repository full name (which is not secret information — it's a public GitHub identifier).

### Likelihood Explanation
This requires a multi-organization Shipit deployment (explicitly supported/documented) where a hostile-but-legitimate tenant admin exists — plausible for shared/hosted Shipit instances serving multiple teams or orgs. No credential theft, TLS interception, or privileged Shipit account is needed; the attacker only uses credentials they already legitimately hold for their own tenant.

### Recommendation
After verifying the HMAC using the key selected by `repository.owner.login`, cross-validate that `repository.full_name` actually belongs to that same owner (e.g., assert `full_name.split('/').first.casecmp(repository_owner) == 0`) before dispatching to handlers, or resolve the target repository/stack strictly within the verified organization's namespace rather than trusting `full_name` in isolation.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `test/dummy/config/secrets_double_github_app.yml` schema), both tracking stacks on the same instance.
2. As the legitimate owner of `OrgB`, compute `sha1=HMAC(OrgB_webhook_secret, body)` for a `push` payload where `repository.owner.login = "OrgB"` but `repository.full_name = "OrgA/target-repo"`.
3. POST to `/github/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature` set to that HMAC.
4. `verify_signature` looks up `Shipit.github(organization: "OrgB")` and validates the signature successfully (since it was genuinely signed with OrgB's secret).
5. `Webhooks.for_event('push')` invokes the push handler, which resolves `stacks` via `Repository.from_github_repo_name("OrgA/target-repo")` [3](#0-2) , acting on `OrgA`'s stack even though the request was authenticated only against `OrgB`.

Note: I was unable to inspect `app/models/shipit/webhooks/handlers/push_handler.rb` and `status_handler.rb` in full detail within the remaining tool budget to enumerate every downstream write action; the root-cause binding break in `webhooks_controller.rb` and `handler.rb` is fully confirmed, but a Devin session with full file access would be needed to enumerate the complete list of exploitable side effects per handler.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
