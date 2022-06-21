.PHONY: test test-internal run-matrix

DOCKER=$(shell which podman 2>/dev/null || which docker)
CONTAINER_IMAGE=docker.io/matrixdotorg/dendrite-monolith:latest
CONTAINER_NAME=test_dentrite

DENDRITE_TEST_USER=test_user
DENDRITE_TEST_PASSWORD=test_password
keys=key.pem server.crt server.key
DENDRITE_KEYS=$(keys:%=.matrix/%)

default: test

run-matrix: $(DENDRITE_KEYS) .matrix/users.db
	@echo "⚒️ Running container \"$(CONTAINER_NAME)\" in background on port 12345"
	$(DOCKER) run -d -p 12345:8008 --rm --name $(CONTAINER_NAME) -v .matrix:/etc/dendrite \
		$(CONTAINER_IMAGE) --tls-cert=server.crt --tls-key=server.key

# generate db with test user account
.matrix/users.db:
	$(DOCKER) run --rm --entrypoint="" -v $(@D):/etc/dendrite $(CONTAINER_IMAGE) \
		/usr/bin/create-account -username $(DENDRITE_TEST_USER) -password $(DENDRITE_TEST_PASSWORD) > /dev/null 2>/dev/null
	sqlite3 -csv $@ ".import '|cat -' account_data" < $(@D)/test_account_data.csv

# generate key files required by dendrite to function
$(DENDRITE_KEYS):
	$(DOCKER) run --rm --entrypoint="" -v $(@D):/mnt $(CONTAINER_IMAGE) \
		/usr/bin/generate-keys -private-key /mnt/key.pem -tls-cert /mnt/server.crt -tls-key /mnt/server.key

# start a dendrite server before running tests and kill it when done
test:
	@bash -c "trap '$(DOCKER) kill $(CONTAINER_NAME)' EXIT; $(MAKE) -s test-internal"

test-internal: run-matrix
	@echo "⏳ Waiting server to be ready"
	@curl localhost:12345/_matrix/client/versions -o /dev/null -fs --retry 5 --retry-all-errors
	cargo test 
