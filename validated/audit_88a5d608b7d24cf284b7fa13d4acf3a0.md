[1](#0-0) [1](#0-0) [2](#0-1)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** test/models/commits_test.rb (L505-533)
```ruby
    test "#state is `unknown` by default" do
      assert_equal 'unknown', @stack.commits.new.state
    end

    test "#state is `success` if all most recent the statuses are `success`" do
      assert_equal 'success', shipit_commits(:third).state
    end

    test "#state is `failure` one of the most recent the statuses is `failure`" do
      assert_equal 'failure', shipit_commits(:second).state
    end

    test "#state is `pending` one of the most recent the statuses is `pending` and none is `failure` or `error`" do
      assert_equal 'pending', shipit_commits(:fourth).state
    end

    test "#state doesn't consider statuses that are hidden or allowed to fail" do
      assert_equal 'pending', @commit.state

      @commit.statuses.create!(stack_id: @stack.id, context: 'metrics/coveralls', state: 'failure')
      @commit.statuses.create!(stack_id: @stack.id, context: 'metrics/performance', state: 'failure')
      assert_equal 'failure', @commit.reload.state

      @commit.stack.update!(cached_deploy_spec: DeploySpec.new('ci' => {
                                                                 'hide' => 'metrics/coveralls',
                                                                 'allow_failures' => 'metrics/performance'
                                                               }))
      assert_equal 'pending', @commit.reload.state
    end
```
