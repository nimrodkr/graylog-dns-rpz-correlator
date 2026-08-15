# Graylog Setup Guide

This guide configures Graylog for the **graylog-dns-rpz-correlator** project.

The goal is to correlate A10 DNS RPZ Policy events with the original DNS Query events and create a clean `RPZ_Match` event containing the client IP, source port, domain, RPZ action, zone, query information, and correlation IDs.

## 1. Message Flow

```text
A10 DNS
   |
   v
Graylog Syslog UDP Input :5140
   |
   +--> DNS Query messages --> Graylog / OpenSearch
   |
   +--> RPZ Policy messages --> RPZ_Policy stream
                                  |
                                  v
                     graylog-dns-rpz-correlator
                                  |
                     correlate Policy + DNS Query
                                  |
                                  v
                     RPZ_Match -> UDP/5140
                                  |
                                  v
                     parse_rpz_match pipeline
                                  |
                                  v
                         RPZ_Matches stream
                                  |
                                  v
                      RPZ Security Dashboard
```

The production correlator does **not** require a Graylog webhook or Event Definition. It polls OpenSearch periodically and uses SQLite to prevent duplicate processing.

## 2. Graylog Syslog Input

Create or use a **Syslog UDP** input.

| Setting | Value |
|---|---|
| Type | Syslog UDP |
| Bind address | `0.0.0.0` |
| Port | `5140` |

Verify incoming A10 Policy messages by searching for:

```text
Policy Zone=
```

Later, verify generated messages with:

```text
RPZ_Match
```

## 3. Create the RPZ_Policy Stream

Create and start a stream named:

```text
RPZ_Policy
```

Suggested description:

```text
A10 DNS RPZ Policy events used by the RPZ correlator
```

## 4. RPZ Policy Routing Rule

Go to:

```text
System -> Pipelines -> Manage rules
```

Create `route_rpz_policy`:

```text
rule "route_rpz_policy"
when
    has_field("message") &&
    contains(
        to_string($message.message),
        "Policy Zone="
    )
then
    route_to_stream(
        name: "RPZ_Policy",
        remove_from_default: false
    );
end
```

Create the pipeline:

```text
Pipeline: RPZ Policy Router
Connection: default_stream
Stage 0: route_rpz_policy
```

Generate an RPZ event and verify it appears under:

```text
Streams -> RPZ_Policy
```

Example A10 Policy message:

```text
<134>Aug 15 19:11:48 ADC-site1-1 a10logd: [ACOS]<6> Policy Zone=a10_rpz, Trigger Type=QNAME, Trigger Reason=www.netflix.com+5, Action Type=nxdomain, Action Detail=
```

## 5. Create the RPZ_Matches Stream

Create and start:

```text
RPZ_Matches
```

Suggested description:

```text
DNS queries correlated with A10 RPZ Policy events
```

This is the primary stream for the RPZ Security Dashboard.

## 6. RPZ Match Parsing Rule

The correlator generates messages similar to:

```text
RPZ_Correlator: RPZ_Match domain=www.netflix.com action=nxdomain client_ip=100.0.0.1 client_port=44768 client_endpoint=100.0.0.1:44768 zone=a10_rpz matched_domain=www.netflix.com query_id=12345 query_type=A policy_id=<policy-id> dns_id=<dns-id>
```

Create the pipeline rule `parse_rpz_match`:

```text
rule "parse_rpz_match"
when
    contains(to_string($message.message), "RPZ_Match")
then
    let domain = regex("domain=([^ ]+)", to_string($message.message));
    let action = regex("action=([^ ]+)", to_string($message.message));
    let client_ip = regex("client_ip=([^ ]+)", to_string($message.message));
    let client_port = regex("client_port=([^ ]+)", to_string($message.message));
    let client_endpoint = regex("client_endpoint=([^ ]+)", to_string($message.message));
    let zone = regex("zone=([^ ]+)", to_string($message.message));
    let matched_domain = regex("matched_domain=([^ ]+)", to_string($message.message));
    let query_id = regex("query_id=([^ ]+)", to_string($message.message));
    let query_type = regex("query_type=([^ ]+)", to_string($message.message));
    let policy_id = regex("policy_id=([^ ]+)", to_string($message.message));
    let dns_id = regex("dns_id=([^ ]+)", to_string($message.message));

    set_field("rpz_domain", domain["0"]);
    set_field("rpz_action", action["0"]);
    set_field("client_ip", client_ip["0"]);
    set_field("client_port", client_port["0"]);
    set_field("client_endpoint", client_endpoint["0"]);
    set_field("rpz_zone", zone["0"]);
    set_field("matched_domain", matched_domain["0"]);
    set_field("query_id", query_id["0"]);
    set_field("query_type", query_type["0"]);
    set_field("policy_id", policy_id["0"]);
    set_field("dns_id", dns_id["0"]);
    set_field("event_type", "rpz_match");

    route_to_stream(
        name: "RPZ_Matches",
        remove_from_default: false
    );
end
```

Create the pipeline:

```text
Pipeline: RPZ Match Processing
Connection: default_stream
Stage 0: parse_rpz_match
```

## 7. Expected RPZ_Match Fields

| Field | Purpose |
|---|---|
| `event_type` | Fixed value `rpz_match` |
| `rpz_domain` | Domain from the RPZ Policy |
| `rpz_action` | RPZ action such as `nxdomain`, `nodata`, or `drop` |
| `client_ip` | DNS client source IP |
| `client_port` | DNS client source UDP port |
| `client_endpoint` | Combined `IP:port`, useful with CGN |
| `rpz_zone` | RPZ Policy zone |
| `matched_domain` | DNS domain matched during correlation |
| `query_id` | DNS Query ID |
| `query_type` | DNS type such as `A` or `AAAA` |
| `policy_id` | OpenSearch ID of the Policy event |
| `dns_id` | OpenSearch ID of the DNS Query event |

## 8. Verify RPZ Correlation

Generate a DNS query matching an RPZ rule:

```bash
dig @100.0.0.9 www.netflix.com
```

Watch the service:

```bash
sudo journalctl -u graylog-dns-rpz-correlator -f
```

A successful correlation should show:

```text
NEW_POLICY ...
DNS_SEARCH ...
DNS_SEARCH_RESULT ...
CANDIDATES ...
SELECTED ...
SENT ...
```

For CGN-aware correlation:

```text
SELECTED ... client_ip=100.0.0.1 client_port=44768 client_endpoint=100.0.0.1:44768
```

In Graylog search:

```text
event_type:rpz_match
```

or open:

```text
Streams -> RPZ_Matches
```

## 9. Duplicate Protection

Default production values:

```text
POLL_INTERVAL_SECONDS=60
LOOKBACK_SECONDS=90
STATE_RETENTION_SECONDS=300
```

The overlapping lookback helps recover from short OpenSearch indexing delays.

Processed Policy IDs are stored in:

```text
/var/lib/graylog-dns-rpz-correlator/state.db
```

Within each polling cycle, one DNS OpenSearch record is assigned to only one Policy event.

```text
1 Policy event -> 1 unused DNS transaction -> 1 RPZ_Match
```

## 10. RPZ Security Dashboard

Create:

```text
RPZ Security Dashboard
```

Build the dashboard using the `RPZ_Matches` stream.

### Total Hits

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Single Number |
| Rows | None |
| Metric | `Count()` |
| Widget Title | `Total Hits` |

### Unique Clients

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Single Number |
| Rows | None |
| Metric | Cardinality |
| Metric Field | `client_endpoint` |
| Widget Title | `Unique Clients` |

Use `client_ip` temporarily if historical messages do not yet contain `client_endpoint`.

### Unique Domains

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Single Number |
| Rows | None |
| Metric | Cardinality |
| Metric Field | `rpz_domain` |
| Widget Title | `Unique Domains` |

### Top Action

Single Number shows the numeric metric rather than the action string, so use a compact Data Table.

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Data Table |
| Row | `rpz_action` |
| Metric | `Count()` |
| Sort | `Count()` - Descending |
| Row Limit | `1` |
| Widget Title | `Top Action` |

### RPZ Matches Over Time

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Line Chart |
| Row | `timestamp` |
| Interval | Auto |
| Metric | `Count()` |
| Sort | `timestamp` - Ascending |
| Widget Title | `RPZ Matches Over Time` |

### Top Blocked Domains

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Data Table |
| Row | `rpz_domain` |
| Metric | `Count()` |
| Sort | `Count()` - Descending |
| Row Limit | `10` |
| Widget Title | `Top Blocked Domains` |

### Top Client IPs

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Data Table |
| Row | `client_ip` |
| Metric | `Count()` |
| Sort | `Count()` - Descending |
| Row Limit | `10` |
| Widget Title | `Top Client IPs` |

### RPZ Actions

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Pie Chart |
| Row | `rpz_action` |
| Metric | `Count()` |
| Sort | `Count()` - Descending |
| Row Limit | `10` |
| Widget Title | `RPZ Actions` |

### RPZ Zones

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Pie Chart |
| Row | `rpz_zone` |
| Metric | `Count()` |
| Sort | `Count()` - Descending |
| Row Limit | `10` |
| Widget Title | `RPZ Zones` |

### Query Types

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Pie Chart |
| Row | `query_type` |
| Metric | `Count()` |
| Sort | `Count()` - Descending |
| Row Limit | `10` |
| Widget Title | `Query Types` |

### Recent RPZ Matches

| Setting | Value |
|---|---|
| Create Type | Aggregation |
| Visualization | Data Table |
| Row 1 | `timestamp` - Descending |
| Row 2 | `client_ip` |
| Row 3 | `client_port` |
| Row 4 | `rpz_domain` |
| Row 5 | `rpz_action` |
| Row 6 | `rpz_zone` |
| Row 7 | `query_type` |
| Metric | `Count()` |
| Row Limit | `20` |
| Widget Title | `Recent RPZ Matches` |

## 11. Useful Graylog Searches

All matches:

```text
event_type:rpz_match
```

Client:

```text
event_type:rpz_match AND client_ip:100.0.0.1
```

CGN-aware endpoint:

```text
event_type:rpz_match AND client_endpoint:"100.0.0.1:44768"
```

Domain:

```text
event_type:rpz_match AND rpz_domain:www.netflix.com
```

NXDOMAIN:

```text
event_type:rpz_match AND rpz_action:nxdomain
```

Zone:

```text
event_type:rpz_match AND rpz_zone:a10_rpz
```

Query type:

```text
event_type:rpz_match AND query_type:A
```

## 12. Troubleshooting

### Policy messages exist but no RPZ_Match

```bash
sudo systemctl status graylog-dns-rpz-correlator
sudo journalctl -u graylog-dns-rpz-correlator -f
```

Look for:

```text
POLICY_SCAN_RESULT
NEW_POLICY
DNS_SEARCH_RESULT
NO_MATCH
NO_UNUSED_MATCH
SENT
```

### Policy exists but DNS query is not found

Default correlation window:

```text
WINDOW_BEFORE_MS=3000
WINDOW_AFTER_MS=1000
```

Check the Policy and DNS timestamps in Graylog.

### RPZ_Match exists globally but not in RPZ_Matches

Verify:

```text
Pipeline: RPZ Match Processing
Connection: default_stream
Stage 0: parse_rpz_match
```

Also verify `RPZ_Matches` is running.

### client_endpoint is missing

Verify the generated message contains:

```text
client_port=
client_endpoint=
```

Then verify the current `parse_rpz_match` rule includes those fields.

### Check UDP/5140

```bash
sudo ss -lunp | grep ':5140'
sudo tcpdump -ni lo udp port 5140
```

### Check SQLite

```bash
sudo sqlite3 /var/lib/graylog-dns-rpz-correlator/state.db
```

Then:

```sql
.tables
.schema processed_policy
SELECT * FROM processed_policy;
```

Do not remove the production state DB while the service is running unless intentionally resetting duplicate protection.

## 13. Final Verification Checklist

- A10 DNS messages arrive at Graylog UDP/5140.
- `Policy Zone=` messages are visible.
- `RPZ_Policy` stream is running.
- `RPZ Policy Router` is connected to `default_stream`.
- `route_rpz_policy` is Stage 0.
- `graylog-dns-rpz-correlator` service is running.
- Service logs show `NEW_POLICY`, `SELECTED`, and `SENT`.
- `RPZ_Match` messages return to Graylog.
- `RPZ Match Processing` is connected to `default_stream`.
- `parse_rpz_match` is Stage 0.
- `RPZ_Matches` stream is running.
- `event_type:rpz_match` returns results.
- `client_ip` and `client_port` are populated.
- `client_endpoint` is populated for CGN-aware visibility.
- The RPZ Security Dashboard displays data.
