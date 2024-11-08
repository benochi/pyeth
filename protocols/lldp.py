from scapy.all import Ether, Raw, sendp
from scapy.layers.l2 import Dot3
import time


def createFrame(
    deviceName,
    portID="1",
    ttl=120,
    systemName="Device",
    systemDesc="Generic Device",
    mgmtAddress="192.168.1.1",
):
    """constructs an LLDP frame with essential TLVs(type-length-value) for chassis ID, Port ID and TTL."""
    chassis_id_tlv = b"\x02\x07\x04" + bytes(deviceName, "utf-8")
    port_id_tlv = b"\x04\x05" + bytes(portID, "utf-8")
    ttl_tlv = b"\x06\x02" + ttl.to_bytes(2, byteorder="big")

    # Optional TLVs
    system_name_tlv = (
        b"\x0a"
        + len(systemName).to_bytes(1, byteorder="big")
        + bytes(systemName, "utf-8")
    )
    system_desc_tlv = (
        b"\x0c"
        + len(systemDesc).to_bytes(1, byteorder="big")
        + bytes(systemDesc, "utf-8")
    )

    # System capabilities (Router + switch encoded as binary flags)
    # example TLV for router/switch capability
    system_capabilities_tlv = b"\x0e\x04\x00\x14\x00\x14"  # Type (0x0e), Length (0x04), Capabilities (0x0014), Enabled (0x0014)

    # management Address TLV
    mgmt_addr_subtype = b"\x01"  # Subtype for ipv4
    mgmt_addr_length = (
        1 + 4 + 1
    )  # Subtype (1) + IP length (4) + Interface Number length (1)
    mgmt_address_tlv = (
        b"\x10"
        + mgmt_addr_length.to_bytes(1, byteorder="big")
        + mgmt_addr_subtype
        + bytes(map(int, mgmtAddress.split(".")))
        + b"\x00"
    )

    # end of LLDPDU TLV
    end_of_lldpdu_tlv = b"\x00\x00"  # Marks the end of the LLDPDU

    # combine TLVs into payload
    lldp_payload = (
        chassis_id_tlv
        + port_id_tlv
        + ttl_tlv
        + system_name_tlv
        + system_desc_tlv
        + system_capabilities_tlv
        + mgmt_address_tlv
        + end_of_lldpdu_tlv
    )

    # build frame
    lldp_frame = Ether(dst="01:80:c2:00:00:0e") / Raw(load=lldp_payload)
    return lldp_frame


def sendLLDPFrame(deviceName, portID="1", interval=30):
    """Sends an LLDPFrame at a default 30 second interval"""
    while True:
        lldp_frame = createFrame(deviceName, portID)
        print(f"[{deviceName}]: Sending LLDP frame to indicate connectivity.")
        sendp(lldp_frame, iface="\\Device\\NPF_{50044AB9-7CBA-4D95-819E-BF34F9ACBADD}", verbose=False)
        time.sleep(interval)