# ReconLedger: Vultr Single-VM Deployment Runbook

Deploy ReconLedger on a single Vultr Cloud Compute VM (Ubuntu 24.04) with complete lab isolation (Blast Radius Zero).

> [!IMPORTANT]
> **Before You Start:**
> - **No keys in the repository:** Never commit `.env` or any secret keys.
> - **Keys only on the VM:** Place API keys and credentials exclusively in `deploy/vultr/.env` on the VM (`chmod 600 deploy/vultr/.env`).
> - **Never paste secrets:** Never paste API keys, passwords, or tokens in chat or conversation prompts.

> **Lab Target Scope Note:** The public web interface only ever targets the two built-in lab containers (`juice-shop` and `dvwa`) on the isolated `reconledger-lab` internal Docker network. Neither lab container publishes any ports to the host or internet, and the control layer never targets arbitrary or external IP addresses.

---

## 1. Create Vultr Account & Apply Hackathon Gift Code
1. Sign up at [https://www.vultr.com/](https://www.vultr.com/).
2. Apply your hackathon promo / gift code under **Billing** -> **Gift Code / Promo**.
3. **Important:** Only use credits; stop if any page asks for a credit card.

## 2. Deploy Cloud Compute VM
1. Go to **Products** -> **Compute** -> **Deploy Server**.
2. Select:
   - **Server Type:** Cloud Compute - Shared CPU
   - **Location:** Any region closest to you
   - **Operating System:** Ubuntu 24.04 LTS x64
   - **Server Size:** Recommend the smallest plan first (1 vCPU / 1 GB RAM, ~$5-6/mo) with the 2 GB swapfile configured by cloud-init. If `make up` is killed for memory during image build or startup, destroy the instance and redeploy with the next size (1 vCPU / 2 GB RAM). Remember: only use credits; stop if any page asks for a card.
   - **SSH Keys:** Add your personal SSH public key
   - **Server Hostname & Label:** `reconledger-vm`
3. Expand **Cloud-Init & User-Data**:
   - Paste the exact contents of [`deploy/vultr/cloud-init.yaml`](cloud-init.yaml).
4. Click **Deploy Now**.
5. Wait ~1-2 minutes until status becomes **Running** and note the VM's public IPv4 address (e.g. `203.0.113.5`).

## 3. SSH into the VM
Connect via SSH as `root` (the default user on Vultr Ubuntu images):
```bash
ssh root@<VM_PUBLIC_IP>
```
Verify cloud-init has finished setting up swap, Docker, and UFW:
```bash
cloud-init status --wait
swapon --show
docker --version
docker compose version
ufw status
```

## 4. Clone the Repository
Clone the repository manually:
```bash
git clone https://github.com/<owner>/reconledger.git
cd reconledger
git checkout vultr-agent-rush
```
*Note:* For a private repository, type a temporary fine-grained read-only personal access token only at git's password prompt. Afterwards, run:
```bash
git config --unset credential.helper || true
```
Do not store the token anywhere on disk.

## 5. Configure Environment
1. Copy the example environment file:
```bash
cp deploy/vultr/.env.example deploy/vultr/.env
chmod 600 deploy/vultr/.env
```
2. Generate a secure Basic Auth password:
```bash
openssl rand -base64 24
```
3. List available models in Vultr's live catalog (no API key needed):
```bash
curl -s https://api.vultrinference.com/v1/models
```
4. Edit `deploy/vultr/.env` with `nano deploy/vultr/.env`:
   - `RECONLEDGER_DOMAIN`: Set to your domain or a free sslip.io subdomain based on your VM IP (e.g. if IP is `203.0.113.5`, set `203-0-113-5.sslip.io`).
   - `WEB_BASIC_AUTH_USER`: Choose an admin username (e.g. `analyst`).
   - `WEB_BASIC_AUTH_PASS`: Paste the generated password.
   - `LLM_PROVIDER`: Set to `vultr` (or leave blank for deterministic rule-based triage).
   - `LLM_API_KEY`: Paste your Vultr Serverless Inference API key (if using `vultr`).
   - `LLM_MODEL`: Set a model from Vultr's live catalog (e.g. `qwen3.8-27b`).
   - `WEB_RATE_LIMIT_PER_MIN=30`
   - `WEB_MAX_ACTIVE_ASSESSMENTS=2`
5. Test the key once with a one-line chat-completions curl that reads the key from the env file without printing it:
```bash
set -a; . deploy/vultr/.env; set +a; curl -s https://api.vultrinference.com/v1/chat/completions -H "Authorization: Bearer $LLM_API_KEY" -H 'Content-Type: application/json' -d '{"model":"'"$LLM_MODEL"'","messages":[{"role":"user","content":"Reply with OK"}]}' | head -c 400
```

## 6. Build and Start Services
Start the full stack (Caddy, Control, Juice Shop, and build the sandbox image):
```bash
make -C deploy/vultr up
```
*(Optional: to also launch DVWA, run `make -C deploy/vultr up-dvwa`)*

Check running containers:
```bash
make -C deploy/vultr ps
```

## 7. Open Web UI
In your browser, visit:
```text
https://<RECONLEDGER_DOMAIN>
```
Log in using your `WEB_BASIC_AUTH_USER` and `WEB_BASIC_AUTH_PASS`.
You can initiate a scan against the sandboxed Juice Shop lab target.

## 8. Run Isolation Check & Containment Demo (Video Artifacts)
Run these commands on the VM and record the terminal for your submission video:

1. **Verify network and port isolation:**
```bash
make -C deploy/vultr isolation-check
```
*Notice:*
- `reconledger-lab` has `Internal: true` and has only lab containers attached.
- Neither `rl-juice` nor `rl-dvwa` has published host ports (`Ports: map[]`).
- `control` has no published ports and is only attached to `edge`.

2. **Verify runtime containment guarantees:**
```bash
make -C deploy/vultr containment
```
*Verify output:*
The demo prints sections `(a)` through `(d)`. Every check line must read `[PASS]` with mode `LIVE docker` (not `DRY RUN`).

Output is automatically saved with a timestamp to `deploy/vultr/out/containment-<timestamp>.txt`.
Copy the saved output file off the VM to your local machine:
```bash
scp root@<VM_PUBLIC_IP>:~/reconledger/deploy/vultr/out/containment-*.txt .
```

---

## 9. Teardown Checklist (Clean Teardown)
When your demonstration / video recording is finished, execute these teardown steps:

1. **Tear down local Docker containers, volumes, and images on the VM:**
```bash
make -C deploy/vultr destroy
```
2. **Revoke GitHub token:**
   - If you used a personal access token for git clone, revoke it now in GitHub Settings -> Developer Settings -> Personal access tokens.
3. **Log into Vultr Console:**
   - Go to [https://my.vultr.com/](https://my.vultr.com/)
4. **Destroy Cloud Compute VM:**
   - Navigate to **Products** -> **Compute**.
   - Select your `reconledger-vm` instance.
   - Click the **...** menu -> **Server Destroy**. Check the box and confirm.
5. **Delete Reserved IPs:**
   - Check **Network** -> **Reserved IPs**; ensure no reserved IP addresses remain.
6. **Delete Snapshots / Backups:**
   - Check **Storage** -> **Snapshots** and remove any snapshots created during testing.
7. **Cancel / Revoke Serverless Inference:**
   - Under **Cloud Inference**, revoke any API keys or subscriptions created for testing.
8. **Verify Billing:**
   - Go to **Billing** -> **Overview** and confirm active hourly run rate is **$0.00/hr** with no active billable instances.
