### Title
Cross-organization/cross-repository commit status forgery via webhook signature scoped to wrong organization - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body, and only checks that the signature is valid for *that* org's secret. Once the signature check passes, the event is dispatched to handlers (e.g. `StatusHandler`) that act on a *different* field of the same unverified payload — the commit `sha` — without re-validating that the sha actually belongs to the repository/organization whose secret was used to authenticate the request. This breaks the binding "organization that authenticated == repository/commit that is written."

### Finding Description
`Shipit::WebhooksController#verify_signature` does: [1](#0-0) 

It picks the app/secret via `repository_owner`, itself read straight from the JSON body: [2](#0-1) 

This means the signature only proves "the sender knows the webhook secret configured for organization X" — it proves nothing about which specific commit/repository the rest of the payload references. Shipit explicitly supports configuring **multiple independent GitHub organizations**, each with its own `webhook_secret`, in a single instance (see `config/secrets.development.shopify.yml` and the equivalent test fixture), so an attacker who legitimately controls (or has been granted) a GitHub App/webhook secret for *one* configured organization can compute a valid `X-Hub-Signature` for arbitrary payload content.

`StatusHandler#process`, dispatched after signature verification passes, does not re-check organization/repository ownership at all — it looks up commits purely by SHA across the entire `commits` table: [3](#0-2) 

Since git SHAs from public/target repositories are typically knowable (e.g., visible in a target's public GitHub repo, PR pages, or leaked in Shipit's own UI/API), an attacker who controls one org's webhook secret can sign a `status` event payload with a SHA belonging to a commit tracked under a completely different organization's stack, and `Commit#create_status_from_github!` will attach that forged status to the victim commit. This status feeds directly into the deployability computation: [4](#0-3) 

which is used by `UndeployedCommit#deploy_disallowed?` and `Stack#deployable?` to gate automatic and manual deploys, and by `Status::Group` to compute overall CI state used for merge/deploy decisions: [5](#0-4) [6](#0-5) 

### Impact Explanation
By forging a `success` status for a required CI context on a targeted commit in a repository/org the attacker does not control, the attacker can flip `Commit#deployable?` to true and unblock `Stack#deployable?`, causing Shipit to trigger an automatic continuous-delivery deploy (`Stack#trigger_continuous_delivery`) or allow a manual deploy that would otherwise have been blocked by real CI failures — an unauthorized deploy of unvetted code. This matches the "unauthorized deploy" High-impact category. Similarly, forged failure/pending statuses could block a legitimate deploy (a denial-of-service variant, which is explicitly out of scope, but the "unauthorized deploy via forged success status" is squarely in scope).

### Likelihood Explanation
Requires: (1) the target Shipit instance configured for multiple GitHub organizations (a documented, supported configuration), (2) the attacker controlling/knowing the webhook secret for *any one* of the configured orgs (e.g., their own org where they are a legitimate admin — no privileged access to the *victim* org or Shipit session/API token is needed), and (3) knowledge of a target commit SHA (generally public). Given Shipit is explicitly designed for multi-tenant/multi-org setups, this is a realistic configuration, and the attack requires only crafting a raw HTTP POST with a computed HMAC — no GitHub App private key, no Shipit session, no repository write access to the victim repo.

### Recommendation
`StatusHandler` (and other handlers) must validate that the commit/stack being acted upon actually belongs to the repository identified in `payload['repository']['full_name']`, and that repository must belong to the same organization whose webhook secret was used to verify the signature (i.e., cross-check `repository_owner` used in `verify_signature` against the repository actually mutated). Concretely, scope `Commit.where(sha: params.sha)` through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` (as `Handler#stacks` already does for other handlers) rather than querying commits globally by SHA.

### Proof of Concept
1. Configure Shipit (per `config/secrets.development.shopify.yml`) with two orgs, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s. Attacker is an admin of `attacker-org` and knows `attacker-org`'s webhook secret (their own GitHub App).
2. Attacker identifies a commit SHA `abc123` belonging to a stack under `victim-org/production-repo` tracked by the same Shipit instance, with a required CI context `ci/tests` currently `pending`/`failure`.
3. Attacker crafts a JSON body:
```json
{
  "sha": "abc123",
  "state": "success",
  "context": "ci/tests",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s webhook secret over the raw body, sets `X-Github-Event: status`, and POSTs to `/webhooks`.
5. `verify_signature` resolves `repository_owner` = `attacker-org`, verifies successfully against `attacker-org`'s secret.
6. `StatusHandler#process` runs `Commit.where(sha: 'abc123')` — matching the victim's commit regardless of organization — and calls `create_status_from_github!`, injecting a forged `success` status for `ci/tests` on `victim-org`'s commit.
7. If this was the last required/blocking status, `Stack#deployable?` for `victim-org/production-repo` becomes true, and continuous delivery (or a subsequent manual deploy request) proceeds on an unvetted commit.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status/group.rb (L24-32)
```ruby
      def initialize(commit, statuses)
        @commit = commit

        visible_statuses = reject_hidden(statuses.to_a.uniq(&:context))
        missing_contexts = required_statuses - visible_statuses.map(&:context)
        visible_statuses += missing_contexts.map { |c| Status::Missing.new(commit, c) }

        @statuses = visible_statuses.sort_by!(&:context)
      end
```

**File:** app/models/shipit/undeployed_commit.rb (L39-41)
```ruby
    def deploy_disallowed?
      !deployable? || !stack.deployable?
    end
```
