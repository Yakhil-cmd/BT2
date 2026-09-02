Confirmed root-cause analog: `WebhooksController#verify_signature` selects the webhook secret/organization to verify against using an attacker-controlled JSON field (`repository.owner.login`, or its fallback `organization.login`), but the handler that actually writes state (`PushHandler`/`Handler#stacks`) resolves the target repository/stack using a *different* field of the same payload (`repository.full_name`). These two fields are never bound together by the signature check, and in multi-org installations some orgs may have no `webhook_secret` configured (`verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank — [1](#0-0) ). This is the same class of bug as the reported `Voter.poke` issue: a value the code trusts for one purpose (boost accounting / here, signature legitimacy) is silently decoupled from the value actually used to update state (vote weight / here, the repository that gets written to).

### Title
Webhook signature verification is keyed off an attacker-controlled organization field decoupled from the repository actually acted upon - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the unauthenticated JSON body [2](#0-1) . The event handlers that subsequently mutate `Stack`/`Repository` state resolve their target using a *different* field from the same body: `repository.full_name` [3](#0-2) . Because the field used to select the trust anchor and the field used to select the mutated resource are never cryptographically bound together, and because an org configured without a `webhook_secret` causes signature checking to be bypassed entirely (`return true unless webhook_secret`), an attacker can satisfy verification for one organization while making the payload's `repository.full_name` point at a stack belonging to a different, fully-protected organization.

### Finding Description
`Shipit.github(organization: repository_owner)` in `verify_signature` resolves the App config purely from `params.dig('repository','owner','login') || params.dig('organization','login')` [4](#0-3) . `GitHubApp#verify_webhook_signature` then does:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [1](#0-0) 
so any organization entry in `secrets.yml` left with `webhook_secret: # nil` (which is the exact shape shown in the documented multi-org config template) accepts **any** signature, including none.

Once `head(422) unless verified` passes, the entire raw JSON body — including `repository.full_name` — is handed unchanged to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) . `Handler#stacks` and `PushHandler#process` resolve the affected `Stack` from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name` [3](#0-2) [6](#0-5) . `repository.owner.login` (used for auth) and `repository.full_name` (used for the write) are two independent fields in the same untrusted JSON body — nothing forces `full_name` to start with `owner.login`.

The binding that should hold and is broken:
`organization whose webhook_secret authenticated the request == owner of the repository whose Stack is mutated`

Before the attack: signature verification org == mutated-repo owner, because both are implicitly assumed to come from the same trustworthy GitHub-signed source.
After the attacker's crafted request: `repository.owner.login` is set to an org with no configured `webhook_secret` (auto-verified), while `repository.full_name` is set to `"protected-org/some-repo"` — a stack belonging to a different, properly-secured organization. The push handler then calls `stack.sync_github(expected_head_sha: ...)` on that protected org's stack using attacker-supplied `ref`/`after` values, all without ever presenting a valid signature for that org.

### Impact Explanation
This crosses exactly the "organization authenticated versus the repository written" trust boundary called out as in-scope. It lets an unauthenticated external attacker force `GithubSyncJob`/other webhook-triggered side effects (e.g. commit status updates, PR label-driven `archive!`/`unarchive!` of review stacks, membership/team creation) against a stack/repository that belongs to a fully-configured, secret-protected organization, purely by picking a different, unprotected `repository.owner.login` value in the same request. Depending on which webhook event is abused (`push`, `pull_request` labeled/unlabeled/reopened/closed, `membership`), this can force spurious syncs, archive/unarchive review stacks, or fabricate commit statuses on a protected stack — none of which require any credential, session, or GitHub write access from the attacker. This satisfies the "cross-repository writes" / unauthorized-mutation impact bar.

### Likelihood Explanation
Requires only that at least one organization in the multi-org `github:` config is left without a `webhook_secret` (explicitly supported and documented as `webhook_secret: # nil` in `docs/setup.md` and the shipped `secrets.development.example.yml`/`secrets_double_github_app.yml` fixtures). Given that shape is the documented default template for adding a second organization, this is a realistic deployment state, not a hypothetical misconfiguration. No signature, no session, no API token is required — the only "cost" to the attacker is knowing/guessing the name of an org configured this way and the `owner/name` of the target repository, both of which are typically public.

### Recommendation
Bind the signature-verification identity to the exact same repository owner used by handlers, and reject (rather than silently pass) organizations with an unset `webhook_secret` in multi-org mode; alternatively, verify the signature independently for every organization configured, and only allow the payload to affect stacks whose `Repository#owner` matches the organization whose secret actually verified the signature.

### Proof of Concept
1. Configure two organizations in `secrets.yml`: `unprotected-org` (no `webhook_secret`) and `protected-org` (`webhook_secret: <strongsecret>`), each with a `Stack` for a repo they own.
2. POST to `/webhooks` with header `X-Github-Event: push` and no/garbage `X-Hub-Signature`, and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "unprotected-org" }, "full_name": "protected-org/some-repo" }
}
```
3. `verify_signature` resolves `Shipit.github(organization: "unprotected-org")`, whose `verify_webhook_signature` returns `true` unconditionally (`webhook_secret` blank) — see `app/controllers/shipit/webhooks_controller.rb:24-30` and `lib/shipit/github_app.rb:76-83`.
4. `PushHandler#process` then loads `Repository.from_github_repo_name("protected-org/some-repo")` and calls `sync_github` on its stacks — `app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/webhooks/handlers/push_handler.rb:12-17` — despite the request never presenting a valid signature for `protected-org`.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
