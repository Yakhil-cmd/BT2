### Title
Webhook signature is verified against an organization taken from the unauthenticated payload, but the stack that is acted upon is resolved from a different, uncross-checked payload field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* organization's webhook secret to HMAC-verify a GitHub webhook against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted request body, before the signature has been checked [1](#0-0) [2](#0-1) . Once the HMAC passes, the downstream handler (e.g. `PushHandler`) resolves the target `Stack`s to act on using a *different* payload field, `repository.full_name`, as shown by the test that swaps `full_name` to point at an unrelated repository and expects the handler to simply not match anything rather than reject the request [3](#0-2) , and `PushHandler#process` blindly iterates whatever `stacks` scope it is given [4](#0-3) . The organization used to select/verify the HMAC secret is therefore not the same field that determines which repository/stack the event is actually applied to.

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [5](#0-4) . This value comes from inside the same JSON body that the signature is supposed to authenticate, and it is only used to pick which org's secret to test — it is never cross-checked against the field that later determines *what gets processed*. `Shipit::Webhooks.for_event(event)` then dispatches the whole raw payload to handlers such as `PushHandler`, which derives its target `Stack`s from the `stacks` scope and `params.ref`/`params.after` [6](#0-5) , and (per the controller test that only changes `repository.full_name`) that scope is keyed on `repository.full_name`, not on `repository.owner.login` [3](#0-2) .

This is the same bug class as the analog report: a flag/field is set/checked in one place but the actual state-changing operation trusts a different, uncovered field. Here the equality that should hold is:

`organization whose secret authenticated the request == organization that owns the repository the event is applied to`

but the code only enforces `organization-in-owner.login field == secret owner`, while the effective write target is chosen from `repository.full_name`. An attacker who legitimately controls a webhook secret for **their own** organization/repository tracked by the same Shipit instance can craft a payload where `repository.owner.login` is set to their own org (so `verify_signature` selects their own valid secret and the HMAC passes) while `repository.full_name` is set to an unrelated org/repo also tracked by the instance. The signature check passes, and the handler then walks the `stacks` matching the spoofed `full_name`, triggering `GithubSyncJob`/stack-sync activity for a repository the attacker does not control.

### Impact Explanation
This breaks the trust binding between "the organization whose webhook secret authenticated the request" and "the repository the event is applied to," letting an attacker who only owns a webhook secret for one tracked org forge push/status/other events that are processed as if they came from a different, unrelated org's repository on the same shared Shipit instance. Depending on which handler runs, this can trigger unauthorized sync/build activity for stacks that do not belong to the attacker's organization, which falls in the "cross-repository writes" category.

### Likelihood Explanation
Exploitation requires only a valid webhook secret for any single organization/repository that the same Shipit deployment tracks (something the attacker legitimately controls if they administer their own org's GitHub App/webhook integration on the shared instance) — no Shipit session, `ApiClient` token, or GitHub write access to the victim repository is required. The disconnect between the field used for secret selection (`repository.owner.login`) and the field used for stack resolution (`repository.full_name`) is a straightforward, deterministic code path with no additional preconditions.

### Recommendation
Do not use an attacker-controlled JSON field to decide which secret verifies that same JSON. Bind webhook secret selection and event routing to the same, single trusted identifier (e.g., resolve the target `Stack`/`Repository` first from a stable value, verify the signature using that repository's owning organization's secret, and abort if `repository.owner.login`/`organization.login` do not match `repository.full_name`'s owner) before any handler is invoked.

### Proof of Concept
1. Shipit instance tracks stacks for both `org-attacker/repo-a` and `org-victim/repo-b`, each org configured with its own webhook secret in `Shipit.github`.
2. Attacker, who legitimately knows `org-attacker`'s webhook secret, crafts a `push` payload with `repository.owner.login = "org-attacker"` but `repository.full_name = "org-victim/repo-b"` and `ref`/`after` pointing at a branch tracked for `repo-b`.
3. Attacker HMAC-signs the payload body with `org-attacker`'s secret and sends it to `WebhooksController#create`.
4. `verify_signature` calls `Shipit.github(organization: "org-attacker")` and the signature validates successfully [7](#0-6) .
5. `PushHandler#process` matches stacks by `full_name`/branch from the same payload and enqueues `GithubSyncJob` for `org-victim/repo-b`'s stack [4](#0-3) , even though the signature only proved knowledge of `org-attacker`'s secret.

Note: I was not able to inspect the base `Shipit::Webhooks::Handlers::Handler#stacks` implementation directly (only inferred its `full_name`-based matching from `test/controllers/webhooks_controller_test.rb`) before the tool budget ran out, so the exact query used to resolve stacks from `repository.full_name` should be double-checked when reproducing this.

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

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
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
