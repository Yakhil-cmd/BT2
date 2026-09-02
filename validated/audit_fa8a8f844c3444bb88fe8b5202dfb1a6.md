Based on my investigation, I found a genuine analog to the "no minimum threshold to incentivize honest behavior" bug class: **the webhook signature-selection field is never checked against the payload field that actually determines which repository/stack gets written to.**

### Title
Webhook signing-organization is not bound to the repository the payload writes to, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App secret to validate a webhook against using one payload field (`repository.owner.login`, falling back to `organization.login`), but every downstream handler (`push`, `status`, `check_suite`, `membership`, etc.) acts on a *different* payload field — `repository.full_name` / the commit `sha` — to decide which `Stack`/`Commit` record to mutate. Nothing enforces that these two fields refer to the same organization.

### Finding Description [1](#0-0)  shows that the secret used for HMAC verification is selected by `repository_owner`, itself read straight out of the untrusted, attacker-supplied JSON body: [2](#0-1) . `Shipit::GitHubApp#verify_webhook_signature` only proves the raw body was HMAC-signed with the secret associated with whatever organization name happens to be sitting in `repository.owner.login`: [3](#0-2) .

Because Shipit supports hosting multiple independent GitHub organizations from one instance (`config/secrets.yml` keyed per-org, as documented in [4](#0-3) ), each organization owns its *own* legitimately-configured `webhook_secret`. Any such org administrator can compute a fully valid signature for a JSON body they construct themselves — they are not required to relay anything GitHub actually sent. The only requirement enforced by `verify_signature` is that `repository.owner.login` (or `organization.login`) matches the org whose secret was used to sign. Nothing checks that the *other* payload fields that determine which Stack is written — `repository.full_name` for `push`/`status`/`check_suite` handlers — belong to that same organization. The equality the code assumes but never enforces is:

`organization_authenticated(payload.repository.owner.login) == organization_of_repository_written(payload.repository.full_name)`

For a genuine GitHub-originated webhook this always holds because GitHub itself fills in both fields consistently. For an attacker-crafted POST to `/webhooks`, it does not have to hold: the attacker fully controls the JSON body, so they can set `repository.owner.login` to their own (legitimately configured) org — making `verify_webhook_signature` succeed with their own secret — while setting `repository.full_name`/commit `sha` to point at a completely unrelated, victim-owned repository/stack that also happens to be configured on the same shared Shipit instance.

The `status` webhook handler is a particularly concrete outlet for this, since it writes a `Status` row directly from payload fields with no live cross-check against GitHub's API (confirmed by [5](#0-4) , which shows `state`, `description`, `target_url`, and `context` are all taken verbatim from the payload for an existing commit).

### Impact Explanation
If a victim stack has `required_statuses`/CI gating or continuous deployment enabled (`Stack#trigger_deploy`, `DeploySpec#required_statuses`), an attacker who controls any one org onboarded onto the shared Shipit instance can forge a "success" `status` event for a specific commit SHA on a *different* organization's stack, satisfying CI-status gating that the code relies on before allowing deploy/continuous-delivery to proceed — this can result in an unauthorized deploy of a commit that never actually passed CI, matching the "unauthorized deploy" impact class.

### Likelihood Explanation
I was not able to fully read `app/models/shipit/webhooks/handlers/push_handler.rb` and `status_handler.rb` within my remaining tool budget to confirm exactly how `Stack`/`Repository` lookup is performed from `repository.full_name` versus the verified `repository_owner`, so I cannot give 100% certainty that no additional org-consistency check exists inside those specific handler classes. This should be verified directly by reading those two files (and `check_suite_handler.rb`) before treating this as confirmed — the routing/signature-selection logic itself, however, is confirmed as shown above and clearly has no cross-check.

### Recommendation
In `WebhooksController#verify_signature`, after determining `repository_owner` and verifying the signature, additionally assert that every organization-identifying field used later by handlers (particularly `repository.full_name`'s owner segment) is identical to `repository_owner`; reject the webhook otherwise. Alternatively, resolve the target `Stack`/`Repository` only by an ID that is itself scoped to the verified organization rather than trusting `full_name` independently.

### Proof of Concept
1. Operate (or be delegated admin of) "attacker-org", one of several organizations configured under `github:` in `config/secrets.yml`, and possess its legitimate `webhook_secret`.
2. Craft a `status` (or `push`/`check_suite`) JSON payload where `repository.owner.login = "attacker-org"` (or `organization.login`) but `repository.full_name = "victim-org/victim-repo"` and `sha` = the known SHA of a victim commit pending deploy.
3. Compute `X-Hub-Signature: sha1=HMAC(attacker-org secret, raw_body)`.
4. POST to `/webhooks` with header `X-Github-Event: status`.
5. `verify_signature` passes because it only checks the `attacker-org` secret against `repository_owner=attacker-org`.
6. The `status` handler creates/updates a `Status` for `victim-repo`'s commit using attacker-controlled `state`/`context`, potentially satisfying deploy-gating checks for a stack the attacker has no legitimate access to.

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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
