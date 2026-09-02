### Title
Webhook signature is verified against the organization derived from the payload, but events are applied to whatever repository/stack the same payload names — cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App / `webhook_secret` to validate a delivery against based on `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) [1](#0-0) . Once the HMAC checks out for *that* organization's secret, the event is dispatched to handlers that resolve the target `Stack`/`Repository` from a **different, independently-attacker-controlled** field of the very same payload: `payload.dig('repository', 'full_name')` [2](#0-1) . Nothing ties `repository.owner.login` (used to pick the secret) to `repository.full_name` (used to pick the target stack). In a Shipit deployment configured for multiple GitHub organizations (a documented, supported configuration) [3](#0-2) , any organization admin who legitimately knows their own `webhook_secret` can sign a payload whose `repository.owner.login` matches their own org (so signature verification passes) while `repository.full_name` names a stack belonging to a completely different, victim organization.

### Finding Description
The equality the engine implicitly relies on is:
`organization whose secret authenticated the request == organization that owns the repository the handler acts on`

This equality is never enforced. `verify_signature` only proves "this HMAC matches organization X's webhook_secret" [4](#0-3) ; it does not constrain which repository the payload may reference. `Handler#stacks` then trusts `repository.full_name` unconditionally to look up `Repository.from_github_repo_name` and the associated stacks [5](#0-4) .

Concretely, `PushHandler` uses this to select any non-archived stack matching the pushed branch and force a resync with an attacker-chosen `expected_head_sha` [6](#0-5) , and other handlers (`status`, `check_suite`, `pull_request/*`) perform similar repository-scoped writes (statuses, check-run refresh, merge-queue mutations) keyed off the same `repository.full_name`/`organization.login` fields that are outside the signature-to-repository binding.

This is the direct analog of the reported bug class: the report's Auction contract validated `totalContractsSold` against a stale/removed order-book state instead of the current global invariant, letting one accounting context "bleed" into another and grant more than was actually collateralized. Here, the webhook pipeline validates a signature against one identity (the signing organization) but applies the resulting trust to a second, unchecked identity (the target repository named in the same payload), letting one org's legitimate signing capability be laundered into writes against another org's stack.

### Impact Explanation
An attacker who administers (or compromises) any one of the multiple GitHub organizations configured on a shared Shipit instance can forge webhook deliveries that are accepted as authentic for **any other configured organization's repositories**. Depending on handler, this allows:
- Forcing `GithubSyncJob`/status refreshes and injecting fabricated commit `Status` rows for a victim stack's commits, which can be used to make an unmerged/malicious commit appear to have passing CI, feeding into merge-queue / continuous-deployment logic that gates automatic merges and deploys — i.e., an unauthorized ship of a commit that never actually passed the victim's CI.
- Creating/removing `Team`/`Membership` records via the `membership` event handler using an `organization.login` the attacker doesn't actually control the real GitHub org for, potentially escalating into `Shipit.github_teams` authorization checks used by `User#authorized?` [7](#0-6) .

This lands squarely in the "High" bucket defined by scope (escalation into `Shipit.github_teams` authorization) and potentially "Critical" (unauthorized deploy/merge) depending on which handler is abused and how continuous deployment/merge-queue gating is configured for the victim stack.

### Likelihood Explanation
Requires the instance to be configured for multiple GitHub organizations (explicitly documented and supported) and the attacker to control one of those organizations' webhook secret — which is a normal, unprivileged-with-respect-to-Shipit capability (they're just an admin of their own, unrelated GitHub org that happens to be configured on the same shared Shipit install). No Shipit session, API token, or GitHub write access to the victim repository is needed. Single-organization deployments are not affected the same way (there `repository_owner` always matches the only configured org), so likelihood is contingent on the multi-org configuration being in use.

### Recommendation
After signature verification succeeds for organization `X`, assert that every repository/organization identifier the handler subsequently reads from the payload (`repository.owner.login`, `repository.full_name`, `organization.login`) is actually within organization `X`'s namespace before resolving stacks or writing records. Reject the event (422) if there is a mismatch, e.g. compare `repository_owner` used for signature selection against the owner segment parsed out of `repository.full_name` in `Handler#stacks`, and thread the verified organization through to each handler instead of only using it once for the HMAC check.

### Proof of Concept
1. Configure two organizations in `config/secrets.yml`: `org-a` (attacker-controlled, secret known to attacker) and `org-b` (victim) [3](#0-2) .
2. Attacker crafts a `push` (or `status`) webhook JSON body where `repository.owner.login = "org-a"` but `repository.full_name = "org-b/victim-repo"`.
3. Attacker signs the raw body with `org-a`'s known `webhook_secret` and sends it to `/webhooks` with `X-Hub-Signature`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and successfully verifies the signature [8](#0-7) .
5. `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }` runs `PushHandler`, which resolves stacks via `Repository.from_github_repo_name("org-b/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack [9](#0-8)  — despite the request only ever being authenticated as `org-a`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** docs/setup.md (L181-209)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
