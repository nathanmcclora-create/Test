import argparse
import time
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
)

IF_OPER_STATUS = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}


def get_interface_status(host, community, if_index, port=161, timeout=1, retries=3):
    oid = ObjectIdentity("1.3.6.1.2.1.2.2.1.8", if_index)
    error_indication, error_status, error_index, var_binds = next(
        getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=0),
            UdpTransportTarget((host, port), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(oid),
        )
    )

    if error_indication:
        raise RuntimeError(f"SNMP error: {error_indication}")
    if error_status:
        raise RuntimeError(
            f"SNMP error: {error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1] or '?'}"
        )

    for _, value in var_binds:
        return int(value)

    raise RuntimeError("No SNMP response received")


def monitor_interface(host, community, if_index, interval=5):
    last_status = None
    while True:
        try:
            status_code = get_interface_status(host, community, if_index)
            status = IF_OPER_STATUS.get(status_code, f"unknown({status_code})")
            if status != last_status:
                print(f"Interface {if_index} on {host} changed to {status}")
                last_status = status
            else:
                print(f"Interface {if_index} on {host} remains {status}")
        except Exception as exc:
            print(f"Failed to read interface {if_index} status: {exc}")
        time.sleep(interval)


def parse_args():
    parser = argparse.ArgumentParser(description="Monitor a switch interface using SNMP")
    parser.add_argument("host", help="Switch IP or hostname")
    parser.add_argument("community", help="SNMP community string")
    parser.add_argument("if_index", type=int, help="Interface index to monitor")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    monitor_interface(args.host, args.community, args.if_index, args.interval)
