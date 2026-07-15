"""Stage 3 (ACTIVE) — port scanning + service/version detection.

naabu finds open TCP ports fast (connect scan, no root needed); nmap -sV then
enriches those host:port pairs with service and version banners.

ACTIVE: sends real packets to the target. Gated behind config.active / --active.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict

from ..models import Service, StageRun
from ..util import iter_json_lines, write_lines
from .. import runner
from .base import Stage, StageContext


class PortScanStage(Stage):
    name = "ports"
    tools = ["naabu", "nmap"]
    active = True
    requires_any_tool = False  # handled explicitly below

    def execute(self, ctx: StageContext, record: StageRun) -> str:
        resolved = [h.name for h in ctx.results.hosts.values() if h.resolved]
        if not resolved:
            return "no resolved hosts to scan"

        sdir = ctx.stage_dir(self.name)
        targets_file = sdir / "targets.txt"
        write_lines(targets_file, resolved)

        # host -> {ports}
        open_ports: dict[str, set[int]] = defaultdict(set)
        host_ip: dict[str, str] = {}

        if runner.have("naabu"):
            self._naabu(ctx, sdir, targets_file, open_ports, host_ip)
        elif runner.have("nmap"):
            self._nmap_discovery(ctx, sdir, targets_file, open_ports, host_ip)
        else:
            return "no port scanner available"

        # Enrich with nmap -sV where possible.
        if ctx.config.nmap_service_scan and runner.have("nmap") and open_ports:
            self._nmap_service(ctx, sdir, open_ports, host_ip)
        else:
            for host, ports in open_ports.items():
                for port in sorted(ports):
                    ctx.results.services.append(
                        Service(host=host, port=port, ip=host_ip.get(host)))

        record.produced = len(ctx.results.services)
        n_hosts = len({s.host for s in ctx.results.services})
        return f"{len(ctx.results.services)} open ports across {n_hosts} hosts"

    # -- naabu ------------------------------------------------------------
    def _naabu(self, ctx, sdir, targets_file, open_ports, host_ip) -> None:
        cmd = ["naabu", "-silent", "-json", "-s", "c",  # connect scan (no root)
               "-l", str(targets_file), "-rate", str(ctx.config.rate_limit),
               "-c", str(ctx.config.threads)]
        ports = ctx.config.ports
        if ports.startswith("top-"):
            cmd += ["-top-ports", ports.split("-", 1)[1]]
        else:
            cmd += ["-p", ports]
        res = runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                         log_dir=sdir, log_name="naabu")
        for obj in iter_json_lines(res.stdout):
            host = (obj.get("host") or obj.get("ip") or "").lower()
            port = obj.get("port")
            if host and isinstance(port, int):
                open_ports[host].add(port)
                if obj.get("ip"):
                    host_ip[host] = obj["ip"]

    # -- nmap fallback discovery -----------------------------------------
    def _nmap_discovery(self, ctx, sdir, targets_file, open_ports, host_ip) -> None:
        ports = ctx.config.ports
        port_arg = ["--top-ports", ports.split("-", 1)[1]] if ports.startswith("top-") \
            else ["-p", ports]
        xml_out = sdir / "nmap_discovery.xml"
        cmd = ["nmap", "-Pn", "-T4", *port_arg, "-iL", str(targets_file),
               "-oX", str(xml_out)]
        runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                   log_dir=sdir, log_name="nmap_discovery")
        self._parse_nmap_xml(xml_out, into_ports=open_ports, host_ip=host_ip)

    # -- nmap service/version --------------------------------------------
    def _nmap_service(self, ctx, sdir, open_ports, host_ip) -> None:
        for host, ports in open_ports.items():
            port_csv = ",".join(str(p) for p in sorted(ports))
            xml_out = sdir / f"nmap_sv_{host}.xml"
            cmd = ["nmap", "-Pn", "-sV", "-T4", "-p", port_csv, host, "-oX", str(xml_out)]
            runner.run(cmd, timeout=ctx.config.timeout_for(self.name),
                       log_dir=sdir, log_name=f"nmap_sv_{host}")
            self._parse_nmap_xml(xml_out, into_services=ctx.results.services,
                                 host_ip=host_ip)

    # -- XML parsing ------------------------------------------------------
    def _parse_nmap_xml(self, xml_path, into_ports=None, into_services=None,
                        host_ip=None) -> None:
        if not xml_path.exists():
            return
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            return
        for host_el in root.findall("host"):
            addr = None
            hostname = None
            for a in host_el.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr")
            names = host_el.find("hostnames")
            if names is not None:
                hn = names.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")
            key = (hostname or addr or "").lower()
            if not key:
                continue
            if addr and host_ip is not None:
                host_ip[key] = addr
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for p in ports_el.findall("port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(p.get("portid"))
                proto = p.get("protocol", "tcp")
                if into_ports is not None:
                    into_ports[key].add(portid)
                if into_services is not None:
                    svc = p.find("service")
                    into_services.append(Service(
                        host=key, port=portid, protocol=proto, ip=addr,
                        service=svc.get("name") if svc is not None else None,
                        product=svc.get("product") if svc is not None else None,
                        version=svc.get("version") if svc is not None else None,
                    ))
