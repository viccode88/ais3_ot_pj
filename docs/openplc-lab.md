# OpenPLC isolated laboratory

1. Put the test host and disposable OpenPLC VM/container on a host-only switch with no route to production
   or the Internet. Record both addresses and verify the target against the hypervisor console—not DHCP
   guesswork. OpenPLC UI and map details vary by version; adapt version-specific steps.
2. Snapshot the VM and back up the OpenPLC project/configuration. Create documented read-only coils and
   registers plus a separate, disposable write range with known reset values. Do not fuzz process I/O.
3. Confirm TCP/502 (or the configured lab port) from the test host, first use a one-register `read`, then
   capture traffic with `tcpdump -i <lab-interface> -w openplc-lab.pcap tcp port 502` or Wireshark.
4. Configure a health request for a known lab register. Start at low rate, generate offline first, review
   the corpus, then explicitly execute. Preserve CLI JSON, PCAP, timestamps, OpenPLC service/application
   logs and VM console observations. Reports must not contain credentials.
5. After testing, stop traffic, repeat the known-good read, inspect service/process and logs, and compare
   expected coil/register state. Restore values or revert the snapshot. If health checks fail, disconnect
   the isolated switch before recovery. Never widen the allowlist to reach a non-test environment.
