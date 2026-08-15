# graylog-dns-rpz-correlator

Correlates A10 DNS RPZ Policy logs with the corresponding DNS Query logs stored
in Graylog/OpenSearch.

The service runs continuously under `systemd`. It polls OpenSearch at a
configurable interval and creates a new `RPZ_Match` syslog message for each
new Policy event that can be correlated to a DNS client.

## Architecture

```text
A10
 |
 v
Graylog Syslog Input
 |
 v
OpenSearch
 |
 | poll every 60 seconds
 v
graylog-dns-rpz-correlator
 |
 +-- find new Policy events
 +-- skip already-processed Policy IDs
 +-- normalize Policy domain
 +-- search DNS messages around Policy timestamp
 +-- choose closest unused DNS transaction
 +-- preserve client IP + source port for CGN
 |
 v
RPZ_Match -> Graylog UDP/5140
```

No Graylog webhook or Event Definition is required.

## Correlation behavior

A Policy message such as:

```text
Policy Zone=a10_rpz, Trigger Type=QNAME,
Trigger Reason=www.facebook.com,
Action Type=nodata
```

is normalized to these DNS candidates:

```text
www.facebook.com
facebook.com
```

The correlator searches DNS Query records around the Policy timestamp.

Default correlation tolerance:

```text
Policy timestamp - 3 seconds
Policy timestamp + 1 second
```

If multiple DNS records match, the service selects the closest DNS transaction
that has not already been assigned to another Policy during the same polling
cycle.

This provides:

```text
1 Policy -> 1 DNS transaction -> 1 RPZ_Match
```

## CGN support

The DNS source port is preserved.

Example client identity:

```text
100.0.0.1:44768
```

The generated RPZ message includes:

```text
client_ip
client_port
client_endpoint
query_id
query_type
policy_id
dns_id
```

This is important when multiple subscribers can share the same public/source IP.

## Duplicate protection

Processed Policy IDs are stored in SQLite:

```text
/var/lib/graylog-dns-rpz-correlator/state.db
```

The same Policy ID will not be sent again while it remains in the state DB.

By default, processed state is retained for 5 minutes:

```text
STATE_RETENTION_SECONDS=300
```

The poll lookback overlaps intentionally:

```text
POLL_INTERVAL_SECONDS=60
LOOKBACK_SECONDS=90
```

That allows the next cycle to recover from short OpenSearch indexing delays
without generating duplicate RPZ messages.

## Generated syslog example

```text
RPZ_Correlator: RPZ_Match \
domain=www.facebook.com \
action=nodata \
client_ip=100.0.0.1 \
client_port=44768 \
client_endpoint=100.0.0.1:44768 \
zone=a10_rpz \
matched_domain=www.facebook.com \
query_id=12345 \
query_type=A \
policy_id=<policy-opensearch-id> \
dns_id=<dns-opensearch-id>
```

## Installation

Clone or copy the project to the Linux server:

```bash
cd graylog-dns-rpz-correlator
chmod +x install.sh
sudo ./install.sh
```

The installer creates:

```text
/opt/graylog-dns-rpz-correlator
/etc/graylog-dns-rpz-correlator
/var/lib/graylog-dns-rpz-correlator
```

and installs:

```text
graylog-dns-rpz-correlator.service
```

## Service operation

Status:

```bash
sudo systemctl status graylog-dns-rpz-correlator
```

Live logs:

```bash
sudo journalctl -u graylog-dns-rpz-correlator -f
```

Restart:

```bash
sudo systemctl restart graylog-dns-rpz-correlator
```

Stop:

```bash
sudo systemctl stop graylog-dns-rpz-correlator
```

The service is enabled automatically at boot by `install.sh`.

Verify:

```bash
systemctl is-enabled graylog-dns-rpz-correlator
```

Expected:

```text
enabled
```

## Configuration

Edit:

```bash
sudo nano /etc/graylog-dns-rpz-correlator/rpz-correlator.env
```

Default configuration:

```text
OPENSEARCH_URL=http://127.0.0.1:9200
OPENSEARCH_INDEX=graylog_*

GRAYLOG_HOST=127.0.0.1
GRAYLOG_PORT=5140

POLL_INTERVAL_SECONDS=60
LOOKBACK_SECONDS=90

WINDOW_BEFORE_MS=3000
WINDOW_AFTER_MS=1000

STATE_DB=/var/lib/graylog-dns-rpz-correlator/state.db
STATE_RETENTION_SECONDS=300
```

After changing configuration:

```bash
sudo systemctl restart graylog-dns-rpz-correlator
```

## Manual test

Stop the service first:

```bash
sudo systemctl stop graylog-dns-rpz-correlator
```

Run one dry-run cycle:

```bash
sudo -u rpzcorrelator \
  /opt/graylog-dns-rpz-correlator/venv/bin/python3 \
  /opt/graylog-dns-rpz-correlator/rpz_correlator.py \
  --once
```

Run one cycle and send results to Graylog:

```bash
sudo -u rpzcorrelator \
  /opt/graylog-dns-rpz-correlator/venv/bin/python3 \
  /opt/graylog-dns-rpz-correlator/rpz_correlator.py \
  --once --send
```

Then start the service again:

```bash
sudo systemctl start graylog-dns-rpz-correlator
```

## Expected runtime log

A successful cycle looks similar to:

```text
POLICY_SCAN_RESULT hits=2
NEW_POLICY ...
CANDIDATES ... clients=100.0.0.40:54680,100.0.0.1:44768
SELECTED ... client_endpoint=100.0.0.40:54680
SENT ...

NEW_POLICY ...
SELECTED ... client_endpoint=100.0.0.1:44768
SENT ...

CYCLE_COMPLETE found=2 sent=2 skipped=0 ...
```

## Graylog pipeline fields

The RPZ_Match parsing rule should extract at least:

```text
event_type
rpz_domain
rpz_action
client_ip
client_port
client_endpoint
rpz_zone
matched_domain
query_id
query_type
policy_id
dns_id
```

Recommended value:

```text
event_type = rpz_match
```

## Updating from Git

After pushing new code:

```bash
cd ~/graylog-dns-rpz-correlator
git pull
sudo ./install.sh
```

The installer preserves the existing environment configuration file and
restarts the service with the updated application.
