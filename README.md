### Results
We put the real-world restuls at anonymous Google Drive:
https://drive.google.com/file/d/1M5MKXQfmAF_Y80CkDxZOStkmyvISNrGJ/view?usp=drive_link

### Modified Tor-Snowflake

This repository redefines the Tor-Snowflake Command Line Client, originally available at https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake

The commit we forked from is https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/commit/9f2cc593e843b6d03a357297586e7db01a959a9f

### Changes

The main behavioral changes are:

- `snowflake/client/lib/rendezvous.go` now loads local CAIDA prefix-to-ASN datasets, extracts the proxy IP address from the broker SDP answer, maps the IP to an ASN, anonymizes the IP with a per-run keyed HMAC-SHA256 hash, and appends timestamped results to `proxy_ASNs.csv`.
- The modified rendezvous flow intentionally returns an error after logging the ASN result so the process retries and continues probing instead of completing a normal client session.
- `snowflake/client/prober.go` was added as a standalone probing loop that repeatedly creates WebRTC offers, contacts the broker, triggers ASN logging, closes the peer connection, and repeats.
- Supporting client changes export broker-channel construction, refine WebRTC peer setup, and isolate per-connection client configuration in the SOCKS accept loop.

In short, the repository evolves from a modified Snowflake client with a static ASN log into a Snowflake measurement/probing fork that continuously discovers proxy IPs, maps them to ASNs, anonymizes them, and stores the results for later analysis.
