from scapy.all import Ether, Raw
import time
import importlib
import threading
from typing import Dict, List, Tuple, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('NetworkEmulator')

class NetworkEmulator:
    def __init__(self):
        self.traffic_log: List[Tuple] = []
        self.devices: Dict = {}
        self.connections: Dict[str, List[str]] = {}
        self.running: bool = True
        self._threads: List[threading.Thread] = []

    def add_device(self, device_name: str, protocol: str = "LLDP", 
                   port_id: str = "1", paths: int = 1) -> None:
        """Add a new device with specified protocol and redundant paths."""
        if device_name in self.devices:
            logger.warning(f"Device {device_name} already exists. Updating configuration.")
        
        self.devices[device_name] = {
            'protocol': protocol,
            'port_id': port_id,
            'paths': paths,
            'active': True
        }
        self.connections[device_name] = []
        logger.info(f"Added Device {device_name} with protocol {protocol} and {paths} path(s)")

    def connect_devices(self, device1: str, device2: str) -> bool:
        """Connect two devices bidirectionally."""
        if not all(dev in self.devices for dev in (device1, device2)):
            logger.error("One or both devices not found in the network")
            return False
            
        if device2 not in self.connections[device1]:
            self.connections[device1].append(device2)
            self.connections[device2].append(device1)
            logger.info(f"Connected {device1} to {device2}")
        return True

    def send_frame(self, device_name: str, interval: int = 30) -> None:
        """Send frames for the device using configured protocol."""
        device_info = self.devices.get(device_name)
        if not device_info:
            logger.error(f"Device {device_name} not found")
            return

        try:
            protocol_module = importlib.import_module(f"protocols.{device_info['protocol'].lower()}")
            create_frame_func = getattr(protocol_module, "createFrame")
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to load protocol {device_info['protocol']}: {e}")
            return

        while self.running and self.devices[device_name]['active']:
            try:
                for path in range(device_info['paths']):
                    frame = create_frame_func(device_name, device_info['port_id'])
                    if frame:
                        logger.info(f"[{device_name}] Sent frame on path {path + 1}")

                        # Log sending frame to connected devices
                        for connected_device in self.connections[device_name]:
                            self.log_frame(frame, "sent", device_name, connected_device)
                            self.emulate_incoming_frame(frame, connected_device, device_name)
                        
                time.sleep(interval)
            except Exception as e:
                logger.error(f"Error in send_frame loop for {device_name}: {e}")
                time.sleep(1)  # Prevent rapid error loops

    def emulate_incoming_frame(self, frame, receiving_device, sending_device):
        """Simulate receiving a frame for a specified device."""
        if receiving_device in self.devices and self.devices[receiving_device]['active']:
            self.log_frame(frame, "received", receiving_device, sending_device)
            logger.info(f"[{receiving_device}] Received frame from {sending_device}")

    def log_frame(self, frame, direction: str, device_name: str, peer_device: str) -> None:
        """Log frame details with timestamps."""
        timestamp = time.time()
        self.traffic_log.append((timestamp, direction, device_name, peer_device, frame))
        logger.debug(
            f"{direction.upper()} Frame at {timestamp:.3f} from {device_name} "
            f"to {peer_device}: {frame.summary()}"
        )

    def start(self) -> None:
        """Start the emulator with all configured devices."""
        self.running = True
        
        # Start sender threads for each device
        for device_name in self.devices:
            sender_thread = threading.Thread(
                target=self.send_frame,
                args=(device_name,),
                daemon=True
            )
            sender_thread.start()
            self._threads.append(sender_thread)

    def stop(self) -> None:
        """Stop all emulator activities gracefully."""
        logger.info("Stopping emulator...")
        self.running = False
        for thread in self._threads:
            thread.join(timeout=1.0)
        self._threads.clear()
        logger.info("Emulator stopped")

if __name__ == "__main__":
    # Example usage
    try:
        # Initialize emulator
        emulator = NetworkEmulator()
        
        # Add devices
        emulator.add_device("Device1", protocol="LLDP", port_id="1", paths=2)
        emulator.add_device("Device2", protocol="LLDP", port_id="2", paths=1)
        
        # Connect devices
        emulator.connect_devices("Device1", "Device2")
        
        # Start emulator
        emulator.start()
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down emulator...")
            emulator.stop()
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
