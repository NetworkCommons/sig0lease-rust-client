# Using the srp client - Step by Step Instruction: from key to registered HTTP service

The examples use the test registrar sig0lease.dev.zenr.io:8053 (TCP only) with zone dev.zenr.io. Change --host, --zone and --server to fit your setup.

## 1. Build the CLI

```sh
cargo build --release -p srp-cli
alias srp=./target/release/srp
```

## 2. Create a key for your host name

```sh
srp keygen --host myweb --zone dev.zenr.io
```

This makes an ECDSA P-256 key for myweb.dev.zenr.io. and saves it in ./keystore/. Use --keystore DIR to keep it somewhere else. Back the key up, because it is what proves you own the name. --force replaces the key, but you lose your claim on the name.

## 3. Optional: preview the signed update without sending it

```sh
srp dump --host myweb --zone dev.zenr.io \
  --addr 192.0.2.10 \
  --service _http._tcp --instance "My Web Server" --port 8080 \
  --txt path=/
```

## 4. Register the host and the HTTP service

```sh
srp register --host myweb --zone dev.zenr.io \
  --addr 192.0.2.10 \
  --service _http._tcp --instance "My Web Server" --port 8080 \
  --txt path=/ \
  --server sig0lease.dev.zenr.io:8053 -v
```

- --addr can be given more than once, for both IPv4 and IPv6.
- --service, --instance and --port must be given together.
- --txt and --subtype can be given more than once.
- Leases default to 2 hours, and to 14 days for the key. Change them with --lease and --key-lease, in seconds.
- TCP is the default. Add --udp to send over UDP, which falls back to TCP if the reply is truncated.
- Add --tls for DNS-over-TLS. The default port is then 853. As RFC 9665 specifies, the connection is encrypted but the registrar's certificate is not checked, so it guards against eavesdroppers only. If --server is a host name, it is sent as SNI. There is no fallback to plain TCP. The test registrar sig0lease.dev.zenr.io has no TLS listener yet.

The output shows the lease the server granted.

## 5. Check the result

sig0lease forwards the records to ns1.free2air.org, so ask that server:

```sh
dig @ns1.free2air.org myweb.dev.zenr.io A
dig @ns1.free2air.org _http._tcp.dev.zenr.io PTR
dig @ns1.free2air.org "My\ Web\ Server._http._tcp.dev.zenr.io" SRV
```

## 6. Keep the registration alive

Add `--daemon` to the register command from step 4:

```sh
srp register --host myweb --zone dev.zenr.io \
  --addr 192.0.2.10 \
  --service _http._tcp --instance "My Web Server" --port 8080 \
  --txt path=/ \
  --server sig0lease.dev.zenr.io:8053 --daemon --rename
```

- The daemon refreshes at 80-85% of the lease the server granted (RFC 9664). If an update fails with a timeout, a network error or SERVFAIL, it retries after 5 s, doubling each time up to 5 min. Any other rejection ends the daemon.
- Ctrl-C or SIGTERM removes the registration and exits. The key keeps its claim on the name until KEY-LEASE runs out.
- `--rename` handles name conflicts (YXDOMAIN). It renames only the name that conflicts: the host becomes myweb-2, and an instance becomes "My Web Server (2)". After 5 tries it gives up; --rename N changes that limit. The new names are not saved. After a restart with the same key the daemon starts from the configured names and ends up on the same renamed names.
- `--rename` also works without `--daemon`.

Without --daemon, you can refresh by running the plain register command again before the lease ends, for example from cron. It has to use the same key.

## 7. Let the client find the registrar

Without --server, the client looks up the registrar in DNS, with the _dnssd-srp._tcp SRV record of the registration domain:

```sh
srp discover --zone dev.zenr.io
srp register --host myweb --zone dev.zenr.io --addr 192.0.2.10 \
  --service _http._tcp --instance "My Web Server" --port 8080
```

- --domain dev.zenr.io finds the registration domain itself, from the dr._dns-sd._udp.dev.zenr.io PTR record, and can replace --zone. Plain --domain tries the search domains of /etc/resolv.conf.
- --tls looks for _dnssd-srp-tls._tcp instead. It never falls back to plain TCP.
- --resolver IP[:PORT] picks the DNS resolver. The default is /etc/resolv.conf. If your router's resolver gives odd answers, try --resolver 8.8.8.8.
- --apex-only looks only at the zone apex, as RFC 9665 says. dev.zenr.io needs the default, because its record sits below the apex zenr.io.
- If a registrar address can't be reached, the next one is tried.

## 8. Use the key with other SIG(0) tools

```sh
srp export-key --host myweb --zone dev.zenr.io --dir ~/keys
srp import-key ~/keys/Kmyweb.dev.zenr.io.+013+12345.private
```

These read and write BIND key files (K<name>+013+<tag>.key and .private), as used by nsupdate -k, dnssec-keygen and sig0namectl. Only ECDSA P-256 keys (algorithm 13) work with SRP. sig0namectl's default ED25519 keys are refused. A suitable key comes from dnssec-keygen -a ECDSAP256SHA256 -T KEY -n HOST myweb.dev.zenr.io.

## 9. Remove the registration

```sh
srp remove --host myweb --zone dev.zenr.io \
  --service _http._tcp --instance "My Web Server" --port 8080 \
  --server sig0lease.dev.zenr.io:8053
```

Pass the same services you registered so their instance names are deleted too. Add --forget-key to also give up the name.
