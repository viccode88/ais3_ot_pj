from __future__ import annotations

import errno
import socket
import time

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget, socket_address
from plcfp.scheduler import BudgetExceeded, ProbeScheduler

DEFAULT_TCP_PORTS = (502, 8080, 8443, 44818, 20000, 4840)


def probe_tcp_ports(
    target: ResolvedTarget,
    scheduler: ProbeScheduler,
    ports: tuple[int, ...] = DEFAULT_TCP_PORTS,
) -> list[Observation]:
    observations: list[Observation] = []
    for port in ports:
        started = time.monotonic()

        def connect(selected_port: int = port) -> int:
            with socket.socket(target.family, socket.SOCK_STREAM) as sock:
                sock.settimeout(scheduler.timeout)
                return sock.connect_ex(socket_address(target, selected_port))

        try:
            result = scheduler.run(connect)
            latency = (time.monotonic() - started) * 1000
            if result == 0:
                state = ProbeState.OBSERVED
                value = True
                error = None
            elif result in {errno.ECONNREFUSED, errno.ECONNRESET}:
                state = ProbeState.ABSENT
                value = False
                error = errno.errorcode.get(result, str(result))
            else:
                state = ProbeState.UNAVAILABLE
                value = None
                error = errno.errorcode.get(result, str(result))
        except BudgetExceeded:
            raise
        except OSError as exc:
            latency = (time.monotonic() - started) * 1000
            state = ProbeState.UNAVAILABLE
            value = None
            error = str(exc)
        observations.append(
            Observation(
                probe_id=f"network.tcp.{port}",
                feature=f"tcp.port.{port}.open",
                value=value,
                state=state,
                latency_ms=round(latency, 3),
                error=error,
            )
        )
    return observations
