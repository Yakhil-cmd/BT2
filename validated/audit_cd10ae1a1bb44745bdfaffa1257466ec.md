### Title
Webhook signature verification org is decoupled from the target repository used by handlers, letting a webhook signed for one (unsecured) GitHub organization act on any tracked stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`), but every event handler determines *which stack/repository to act on* using a different payload field: `repository.full_name` (via `Handler#repository_name`). Nothing cross-checks that these two fields refer to the same organization/repository. Combined with the fact that `webhook_secret` is an optional, documented per-organization setting (`nil` is a valid, non-privileged configuration shown in `config/secrets.development.example.yml` and `docs/setup.md`), any organization configured without a secret becomes a skeleton key that lets an unauthenticated attacker forge webhook events against *any other* tracked repository/stack in the same Shipit instance.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does this: [1](#0-0) 
It picks the app/secret to verify against using `repository_owner`: [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly no-ops when no secret is configured for that organization: [3](#0-2) 

Meanwhile, every handler resolves the actual target repository from a *separate* field, `repository.full_name`, never compared to `repository.owner.login`/`organization.login` used above: [4](#0-3) 
`PushHandler` uses that to enqueue a sync of the matched stack's git history: [5](#0-4) 
`StatusHandler` writes a CI status onto any `Commit` matching an attacker-chosen sha, with no repository/organization scoping at all: [6](#0-5) 

Both `webhook_secret: # nil` in `config/secrets.development.example.yml` and the setup docs ("If you've set a webhook secret during the App creation, you should copy it here" — implying it's optional) confirm this is a supported, non-privileged deployment state, not a misconfiguration requiring special credentials: [7](#0-6) [8](#0-7) 

**Binding broken (equality that should hold but doesn't):**
`organization whose secret authenticated the signature == organization/repository the handler actually writes to`.

Before the attack: the signature check is supposed to guarantee that only the true owner of the *target repository* being written to can trigger the handler side effects.
After the attack: an attacker who knows (or exploits the absence of) the webhook secret for organization *A* can produce a payload where `repository.owner.login`/`organization.login` = *A* (satisfies the signature check, trivially if *A* has no secret configured) while `repository.full_name` = `B/some-tracked-repo` — a completely different, unrelated tracked repository *B* that the attacker has no relationship to. The handler then acts on *B*'s stack/commits with no further check.

### Impact Explanation
This crosses the "unauthenticated read of stack state" / "unauthorized deploy" boundary called out as accepted High/Critical impact classes, because:
- `PushHandler` will enqueue `GithubSyncJob` for `B`'s stack using an attacker-controlled `expected_head_sha`, which fetches commits via `stack.github_api` for repository `B`.
- `StatusHandler` lets the attacker create arbitrary CI `Status` records (`state`, `context`, `description`, `target_url`) on any commit sha that exists for stack `B`, without any ownership check tying the forged status to organization `A`. Since deploy/merge gating in Shipit (e.g. `Stack`/`CommitChecks`/`MergeRequest` logic driving required statuses and mergeability) consumes these `Status` rows, an attacker able to inject arbitrary CI status for a commit on repository `B` can influence whether that commit is treated as passing its required checks, which downstream merge-queue/deploy safety logic in this engine (`app/models/shipit/commit_checks.rb`, `app/models/shipit/merge_request.rb`) may rely on for automated merging/deployment eligibility.
- `MembershipHandler` (for the `membership` event, which uses `organization.login` directly as both the verification key and the field written) is not itself cross-organization exploitable by this particular full_name/owner.login mismatch (its handler field equals the verification field), so team-membership escalation is not directly reachable through this specific field-mismatch; the push/status path is the concrete cross-repository-write vector.

This is a genuine credential/authentication boundary crossing: the whole point of the per-organization webhook secret is to bind "who can act" to "which repository is acted upon," and that binding is broken here because verification and target-resolution consult different, uncorrelated fields of the same unsigned-relationship JSON body.

### Likelihood Explanation
Likelihood depends on deployment topology: this is concretely and trivially exploitable in the common documented multi-tenant configuration (`docs/setup.md`, "Using Multiple Github Applications") whenever at least one configured organization has `webhook_secret` unset — a state the shipped example config file treats as the default (`webhook_secret: # nil`). In that state, no credential of any kind is required by the attacker; they can send a raw HTTP POST that will be accepted by `verify_webhook_signature` (`return true unless webhook_secret`) and freely target any other organization's tracked repository through the mismatched `full_name` field. In single-organization deployments, the exposure is smaller (the attacker still needs the possibility of that single org lacking a secret) but the underlying decoupling of "verified org" and "acted-upon repo" is a defect regardless of tenant count.

### Recommendation
- In `Handler#stacks`/`repository_name`, validate that `payload.dig('repository', 'owner', 'login')` (or `payload.dig('organization', 'login')`) matches the owner encoded in `repository.full_name` before resolving/acting on a stack; reject the event otherwise.
- Alternatively/additionally, have `WebhooksController#verify_signature` derive `repository_owner` strictly from `repository.full_name`'s owner segment (the same field handlers use) rather than the separate `repository.owner.login`, so verification and dispatch are provably bound to the same value.
- Treat organizations with no configured `webhook_secret` as unable to receive/act on webhooks for any *other* organization's repositories — i.e., scope trust per-organization consistently across both the signature check and the handler's repository resolution.

### Proof of Concept
1. Deploy Shipit configured for two GitHub organizations, `attacker-org` (no `webhook_secret` set, per the documented optional setting) and `victim-org` (tracked stack for `victim-org/critical-repo`, with its own secret).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/critical-repo"
  }
}
```
No `X-Hub-Signature` (or any arbitrary value) is required, because `Shipit.github(organization: "attacker-org")` has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally at `lib/shipit/github_app.rb:76-83`.
3. `WebhooksController#create` dispatches to `PushHandler`, which resolves the target stack via `repository.full_name` = `victim-org/critical-repo` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and enqueues `GithubSyncJob` for that stack, entirely bypassing any actual relationship between the attacker and `victim-org`.
4. Repeat with `X-Github-Event: status` and a known commit sha on `victim-org/critical-repo` to inject an arbitrary CI status via `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`).

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** docs/setup.md (L117-120)
```markdown
**`github.bot_login`** The login of the App [bot] user. Every GitHub App have an associated `[bot]` user which acts as the author of the App actions through the API, for example when an App merges a Pull Request. It should be the App "slug" with the suffix `[bot]`. For example if your app settings URL is `https://github.com/organizations/ACME/settings/apps/acme-shipit/installations`, the bot user should be `acme-shipit[bot]`. If you are unsure, you can leave it empty.

**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.

```
