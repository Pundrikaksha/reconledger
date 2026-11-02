SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -c

.PHONY: up up-dvwa ps logs containment isolation-check down destroy

COMPOSE ?= docker compose -f docker-compose.yml

up:
	$(COMPOSE) --profile build build sandbox-image
	$(COMPOSE) up -d --build

up-dvwa:
	$(COMPOSE) --profile build build sandbox-image
	$(COMPOSE) --profile dvwa up -d --build

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f

containment:
	@mkdir -p out
	$(eval TS := $(shell date +%Y%m%d-%H%M%S))
	$(COMPOSE) exec -T control reconledger demo-containment 2>&1 | tee out/containment-$(TS).txt

isolation-check:
	@echo "=== 1. Checking reconledger-lab network (Internal flag and attached containers) ==="
	@docker network inspect reconledger-lab --format 'Network: {{.Name}} | Internal: {{.Internal}}'
	@docker network inspect reconledger-lab --format 'Containers: {{range $$k, $$v := .Containers}}{{$$v.Name}} ({{$$v.IPv4Address}}) {{end}}'
	@echo ""
	@echo "=== 2. Inspecting rl-juice (no published ports, network sandbox-lab only) ==="
	@docker inspect rl-juice --format 'Container: {{.Name}} | Ports: {{.NetworkSettings.Ports}} | Networks: {{range $$k, $$v := .NetworkSettings.Networks}}{{$$k}} {{end}}'
	@echo ""
	@echo "=== 3. Inspecting rl-dvwa (if running: no published ports, network sandbox-lab only) ==="
	@-docker inspect rl-dvwa --format 'Container: {{.Name}} | Ports: {{.NetworkSettings.Ports}} | Networks: {{range $$k, $$v := .NetworkSettings.Networks}}{{$$k}} {{end}}' 2>/dev/null || echo "rl-dvwa is not running (start with: make up-dvwa)"
	@echo ""
	@echo "=== 4. Inspecting control (no published ports, network edge only) ==="
	@docker inspect $$( $(COMPOSE) ps -q control ) --format 'Container: {{.Name}} | Ports: {{.NetworkSettings.Ports}} | Networks: {{range $$k, $$v := .NetworkSettings.Networks}}{{$$k}} {{end}}'

down:
	$(COMPOSE) --profile dvwa down

destroy:
	$(COMPOSE) --profile dvwa --profile build down -v --rmi local
	-docker rmi reconledger-sandbox:latest 2>/dev/null || true
	@echo ""
	@echo "================================================================="
	@echo "Local teardown complete. Next, destroy cloud resources manually:"
	@echo "================================================================="
	@echo "1. Log into your Vultr Customer Portal: https://my.vultr.com/"
	@echo "2. Navigate to 'Products' -> 'Compute'."
	@echo "3. Locate your ReconLedger VM instance."
	@echo "4. Click the '...' menu on the right and select 'Server Destroy'."
	@echo "5. Check the confirmation checkbox and click 'Destroy Server'."
	@echo "6. Go to 'Network' -> 'Reserved IPs' and delete any reserved IPs."
	@echo "7. Go to 'Storage' -> 'Snapshots' / 'Backups' and delete any ReconLedger snapshots."
	@echo "8. Go to 'Cloud Inference' / 'Serverless Inference' and cancel any active subscription/keys."
	@echo "9. Check 'Billing' -> 'Overview' to confirm $$0/hr active run rate."
	@echo "================================================================="
