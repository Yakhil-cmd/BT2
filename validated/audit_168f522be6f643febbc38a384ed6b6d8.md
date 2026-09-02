### Title
Webhook signature verified against `repository.owner.login`'s secret but handlers act on `repository.full_name`, allowing cross-tenant repository/stack mutation - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC secret) using `repository_owner`, which is read from `payload.dig('repository', 'owner', 'login')` (or `organization.login`), while every push/pull-request handler resolves the target stack using `payload.dig('repository', 'full_name')`. Since these are two independently attacker-controlled fields in the same JSON body, an attacker who owns `org-a` and knows only `org-a`'s webhook secret can forge a signed request whose `owner.login` is `org-a` but whose `full_name` is `org-b/private-repo`, causing `PushHandler` to call `stack.sync_github` on an org-b stack that never validated the request.

### Finding Description
The broken binding, stated explicitly: the organization whose `webhook_secret` verified the raw request bytes (call it `Org_sig = repository_owner` from `app/controllers/shipit/webhooks_controller.rb:59-62`, `Org_sig = payload.dig('repository','owner','login')`) must equal the organization that owns the repository the handler subsequently mutates (`Org_target`, derived in `app/models/shipit/webhooks/handlers/handler.rb:36-38` as the owner prefix of `payload.dig('repository','full_name')`). Nothing in the code enforces `Org_sig == Org_target`.

Code path:
1. `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` runs first — `app/controllers/shipit/webhooks_controller.rb:6`.
2. `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(header, request.raw_post)` — `app/controllers/shipit/webhooks_controller.rb:24-30`. `verify_webhook_signature` in `lib/shipit/github_app.rb:76-83` is a pure HMAC-SHA1 check of the raw bytes against that one organization's `webhook_secret`; it has no knowledge of, or check against, `full_name`.
3. `#create` re-parses the same `request.raw_post` and dispatches to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` — `app/controllers/shipit/webhooks_controller.rb:10-15`.
4. `PushHandler#process` resolves `stacks` via `Handler#stacks`/`#repository_name`, which reads `payload.dig('repository', 'full_name')` — `app/models/shipit/webhooks/handlers/handler.rb:32-38` — and looks it up with `Repository.from_github_repo_name`, splitting on `/` to get `owner`/`name` and doing a plain `find_by` — `app/models/shipit/repository.rb:53-56`. It then calls `stack.sync_github(expected_head_sha: params.after)` on every matching, non-archived stack whose branch matches `params.ref` — `app/models/shipit/webhooks/handlers/push_handler.rb:12-17`.

Because `repository_owner` (used for auth) and `full_name` (used for the actual mutation) are read from two separate, independently attacker-settable JSON fields in the same body, and the HMAC only certifies "these bytes were signed with org-a's secret" — not "the repository field's owner is org-a" — an attacker who owns `org-a` can craft `repository.owner.login: "org-a"` (satisfies signature check) alongside `repository.full_name: "org-b/private-repo"` (drives the mutation) and pass a fully valid signature computed with their own secret.

None of the existing guards catch this: `verify_signature` never compares its selected organization to `full_name`'s owner; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `PushHandler` (`requires :ref; requires :after`) does not require or validate `repository.full_name` against `repository.owner.login`; there is no `force_github_authentication`/`User#authorized?`/`require_permission!` involved at all since this is an unauthenticated webhook endpoint; `Repository.from_github_repo_name` performs no ownership cross-check, just a DB lookup by whatever owner/name pair is supplied.

### Impact Explanation
A single forged request causes `Stack#sync_github` to run for an arbitrary target stack in `org-b`, using attacker-supplied `ref`/`after` (expected head SHA) values, without org-b's `webhook_secret` ever being validated. This is a cross-tenant write into another organization's stack triggered by data the victim organization never authenticated — matching the Critical category "a payload for one repository mutating another's stack." It is repeatable against any repository/stack whose owner+name the attacker can guess or discover (repository slugs are commonly public), as long as the attacker controls any one organization configured in Shipit with its own `webhook_secret`.

### Likelihood Explanation
Preconditions: Shipit must be configured in multi-organization mode (`Shipit.github(organization:)` config keyed by org, e.g., `org-a` and `org-b` each with a distinct `webhook_secret`), and `org-b` must have a `Stack` whose `branch` matches the attacker-chosen `ref`. Attacker cost is low: they only need to be a legitimate GitHub user/owner of `org-a` (or control a repo webhook under `org-a`), which they can set up trivially, then craft an arbitrary JSON body and sign it with their own known secret. No privileged Shipit role, session, API token, or org-b secret is required. This is fully repeatable and scriptable against any number of target repositories.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`/`PushHandler`), after computing `repository_owner` for signature verification, require that it match the owner segment of `payload.dig('repository', 'full_name')` (and of `organization.login` if used as fallback) before processing, rejecting the request (e.g., `head(422)`) on mismatch. Alternatively, derive `repository_owner` from `full_name`'s owner segment directly instead of `repository.owner.login`, so the same value is used both for secret selection and for the mutation target, eliminating the possibility of divergence.

### Proof of Concept
Add a minitest `ActionDispatch::IntegrationTest` in `test/controllers/shipit/webhooks_controller_test.rb` style:
1. Configure two orgs in test credentials/secrets: `org-a` with `webhook_secret: "secret-a"`, `org-b` with `webhook_secret: "secret-b"`.
2. Create a real `Shipit::Stack` under a `Shipit::Repository` with `owner: "org-b"`, `name: "private-repo"`, `branch: "main"`.
3. Build a JSON push payload body with `repository.owner.login = "org-a"`, `repository.full_name = "org-b/private-repo"`, `ref = "refs/heads/main"`, `after = "<attacker-chosen sha>"`.
4. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', "secret-a", body)` (attacker only knows `secret-a`).
5. POST to `/webhooks` with header `X-Github-Event: push` and the computed signature.
6. Assert the response is `200 OK` (signature accepted).
7. Assert `Shipit::Stack#sync_github` was invoked (e.g., via `Stack.any_instance.expects(:sync_github).with(expected_head_sha: "<attacker sha>")`) on the `org-b` stack — proving `Org_sig ("org-a") != Org_target ("org-b")` yet the mutation proceeded. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
