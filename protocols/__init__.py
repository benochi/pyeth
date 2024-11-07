from scapy.all import Ether, Raw, sendp
from scapy.layers.l2 import Dot3
import time


def createLLDPFrame(deviceNAme, portID="1", ttl=120):
    """constructs an LLDP frame with essential TLVs(type-length-value) for chassis ID, Port ID and TTL."""
    chassis_id_tlv = b"\x02\x07\x04" + bytes(deviceName, "utf-8")
    port_id_tlv = b"\x04\x05" + bytes(portId, "utf-8")
    ttl_tlv = b"\x06\x02" + ttl.to_bytes(2, byteorder="big")
    end_of_lldpdu_tlv = b"\x00\x00"  # Marks the end of the LLDPDU

    # combine TLVs into payload
    lldp_payload = chassis_id_tlv + port_id_tlv + ttl_tlv + end_of_lldpdu_tlv

    # build frame
    lldp_frame = Ether(dst="01:80:c2:00:00:0e") / Raw(load=lldp_payload)
    return lldp_frame


def sendLLDPFrame(deviceNAme, portID="1", interval=30):
    """Sends an LLDPFrame at a default 30 second interval"""
    while True:
        lldp_frame = createLLDPFrame(deviceName, portID)
        print(f"[{deviceName}]: Sending LLDP frame to indicate connectivity.")
        sendp(lldp_frame, iface="lo", verbose=False)
        time.sleep(interval)
