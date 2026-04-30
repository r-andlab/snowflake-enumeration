
# Real-World Enumeration

This repository redefines the Tor-Snowflake Command Line Client, originally available at https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake, for the purposes of our real-world enumeration experiment. 

### Modifications to Snowflake Client

The main behavioral changes are:

- `snowflake/client/lib/rendezvous.go` now loads local CAIDA prefix-to-ASN datasets, extracts the proxy IP address from the broker SDP answer, maps the IP to an ASN, anonymizes the IP with a per-run keyed HMAC-SHA256 hash, and appends timestamped results to `proxy_ASNs.csv`.
- The modified rendezvous flow intentionally returns an error after logging the ASN result so the process retries and continues probing instead of completing a normal client session.
- `snowflake/client/prober.go` was added as a standalone probing loop that repeatedly creates WebRTC offers, contacts the broker, triggers ASN logging, closes the peer connection, and repeats.
- Supporting client changes export broker-channel construction, refine WebRTC peer setup, and isolate per-connection client configuration in the SOCKS accept loop.

### Running the Prober
1. To use the prober, hardcode the client NAT setting first at `snowflake/client/lib/rendezvous.go#L396` 

2. Move to client directory: `cd snowflake/client/`

3. Start the prober using `go prober.go`

4. Enumeration results will be stored in snowflake/client/proxy_ASNs.csv

Note: We caution against using the prober heavily against the live Snowflake broker, as it may cause technical disruptions (see paper for safety details). 

### Results
Aggregate real-world measurement data from our 48-day enumeration study is available at:
https://drive.google.com/file/d/1M5MKXQfmAF_Y80CkDxZOStkmyvISNrGJ/view?usp=drive_link

Raw Snowflake IP addresses and keyed hashes are withheld to protect the privacy of volunteer proxy operators. 
