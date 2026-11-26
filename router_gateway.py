"""Read the gateway of an associated Wi-Fi adapter without initiating a scan."""
from __future__ import annotations

import ipaddress
import platform
import uuid
from typing import NamedTuple

from wifi_scanner import list_wifi_adapters, normalize_bssid, run_command, split_nmcli_line


class GatewayResult(NamedTuple):
    address: str | None
    status: str


class Association(NamedTuple):
    interface: str
    bssid: str
    ssid: str


class GatewayUnavailable(Exception):
    pass


def _linux_associations():
    active = set()
    for device in list_wifi_adapters('Linux'):
        output = run_command(['nmcli', '-t', '-e', 'yes', '-f', 'IN-USE,BSSID,SSID',
                              'device', 'wifi', 'list', 'ifname', device, '--rescan', 'no'], timeout=5)
        for row in output.splitlines():
            data = split_nmcli_line(row)
            if len(data) == 3 and data[0].strip() == '*':
                mac = normalize_bssid(data[1])
                if mac:
                    active.add(Association(device, mac, data[2]))
    return active


def _windows_associations():
    try:
        listing = run_command(['netsh', 'wlan', 'show', 'interfaces'], timeout=8)
    except RuntimeError as exc:
        _check_windows_access(str(exc))
        raise
    # Read the whole interface block. The GUID need not precede the BSSID.
    active = set()
    blocks = []
    fields = {}
    for line in listing.splitlines():
        key, sep, value = line.partition(':')
        key = key.strip().casefold()
        if not sep or not key:
            continue
        if key in ('name', 'имя') or ('guid' in key.split() and 'guid' in fields):
            blocks.append(fields)
            fields = {}
        if 'guid' in key.split():
            fields['guid'] = value.strip()
        elif key == 'ssid':
            fields['ssid'] = value.strip()
        elif 'bssid' in key.split() and normalize_bssid(value):
            fields['bssid'] = normalize_bssid(value)
    for block in [*blocks, fields]:
        if block.get('bssid'):
            try:
                interface = str(uuid.UUID(block.get('guid', '')))
            except ValueError:
                continue
            active.add(Association(interface, block['bssid'], block.get('ssid', '')))
    if not active:
        _check_windows_access(listing)
    return active


def _check_windows_access(output):
    message = output.casefold()
    if any(term in message for term in ('access is denied', 'отказано в доступе',
                                         'location permission', 'геолокац', 'местоположен')):
        raise GatewayUnavailable('Windows ограничила доступ к Wi-Fi')


def _ipv4_values(lines):
    addresses = set()
    for line in lines:
        try:
            ip = ipaddress.IPv4Address(line.strip())
        except ValueError:
            continue
        if not (ip.is_unspecified or ip.is_multicast or ip.is_loopback or int(ip) == 0xffffffff):
            addresses.add(str(ip))
    return addresses


def _linux_gateways(interface):
    try:
        output = run_command(['nmcli', '-g', 'IP4.GATEWAY', 'device', 'show', interface], timeout=6)
        addresses = _ipv4_values(output.splitlines())
        if addresses:
            return addresses
    except (RuntimeError, OSError):
        pass
    # The scope matters on PCs with Ethernet or a VPN.
    try:
        routes = run_command(['ip', '-4', 'route', 'show', 'default', 'dev', interface], timeout=5)
    except (RuntimeError, OSError):
        routes = ''
    hops = []
    for row in routes.splitlines():
        fields = row.split()
        if fields[:2] == ['default', 'via'] and len(fields) >= 3:
            hops.append(fields[2])
    addresses = _ipv4_values(hops)
    if addresses:
        return addresses
    # A local-only Wi-Fi profile can receive DHCP option 3 without installing a default route.
    lease = run_command(['nmcli', '-g', 'DHCP4.OPTION', 'device', 'show', interface], timeout=5)
    for row in lease.splitlines():
        key, _, value = row.partition('=')
        if key.strip() == 'routers':
            hops.extend(value.split())
    return _ipv4_values(hops)


def _windows_gateways(interface):
    # The identifier comes from uuid.UUID, never from a profile or adapter name.
    script = (
        '[System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | '
        "Where-Object { $_.Id.Trim('{}') -eq '" + interface + "' } | "
        'ForEach-Object { $_.GetIPProperties().GatewayAddresses } | '
        "Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } | "
        'ForEach-Object { $_.Address.ToString() }')
    output = run_command(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], timeout=8)
    return _ipv4_values(output.splitlines())


def _select(active, bssid, ssid):
    matches = [a for a in active if a.bssid == bssid]
    if not matches and ssid and ssid != '--':
        matches = [a for a in active if a.ssid == ssid]
    if len(matches) > 1:
        raise GatewayUnavailable('Подходят несколько адаптеров')
    if not matches:
        raise GatewayUnavailable('Подключена другая точка' if active else 'Нет активной точки Wi-Fi')
    return matches[0]


def find_gateway(bssid, ssid=''):
    """An explicit SSID permits a match after roaming; BSSID takes priority."""
    bssid = normalize_bssid(bssid)
    system = platform.system()
    if not bssid or system not in ('Windows', 'Linux'):
        return GatewayResult(None, 'Поиск недоступен')
    associations = _windows_associations if system == 'Windows' else _linux_associations
    gateways = _windows_gateways if system == 'Windows' else _linux_gateways
    try:
        try:
            match = _select(associations(), bssid, ssid)
        except (RuntimeError, OSError):
            raise GatewayUnavailable('Не удалось прочитать состояние Wi-Fi')
        try:
            addresses = gateways(match.interface)
        except (RuntimeError, OSError):
            raise GatewayUnavailable('Не удалось прочитать маршруты')
        if not addresses:
            raise GatewayUnavailable('У Wi-Fi нет IPv4-шлюза')
        if len(addresses) > 1:
            raise GatewayUnavailable('У Wi-Fi несколько шлюзов')
        if _select(associations(), bssid, ssid) != match:
            raise GatewayUnavailable('Подключение изменилось')
        status = 'Шлюз найден' if match.bssid == bssid else 'Шлюз сети · другая точка'
        return GatewayResult(addresses.pop(), status)
    except GatewayUnavailable as error:
        return GatewayResult(None, str(error))
    except (RuntimeError, OSError):
        return GatewayResult(None, 'Не удалось перепроверить Wi-Fi')


def current_gateway(bssid):
    return find_gateway(bssid).address
