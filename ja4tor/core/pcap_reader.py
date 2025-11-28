import os
from pathlib import Path

import pyshark
from scapy.all import Ether
from logger import logger

DEFAULT_TSHARK_PATHS = [
    os.environ.get("TSHARK_PATH"),
    # wireshark PATH
]


class PcapReader:
    def __init__(self, pcap_path):
        if not pcap_path:
            raise ValueError("PCAP path cannot be None or empty.")
        self.pcap_path = pcap_path
        self.tshark_path = self._resolve_tshark_path()

    @staticmethod
    def _resolve_tshark_path():
        for candidate in DEFAULT_TSHARK_PATHS:
            if not candidate:
                continue
            if Path(candidate).is_file():
                logger.info(f"using tshark: {candidate}")
                return candidate
        logger.warning("tshark no found")
        return None

    def read_packets(self):
        logger.info(f"Starting to read packets from {self.pcap_path}")
        try:
            capture_kwargs = dict(
                use_json=True,
                include_raw=True,
                keep_packets=False,
            )
            if self.tshark_path:
                capture_kwargs["tshark_path"] = self.tshark_path

            pyshark_capture = pyshark.FileCapture(self.pcap_path, **capture_kwargs)
            for pyshark_pkt in pyshark_capture:
                scapy_pkt = None
                try:
                    raw_packet_hex = pyshark_pkt.frame_raw.value
                    scapy_pkt = Ether(bytes.fromhex(raw_packet_hex))
                except (AttributeError, ValueError) as exc:
                    logger.debug(
                        f"Could not convert packet {getattr(pyshark_pkt, 'number', '?')} to scapy: {exc}"
                    )

                yield (pyshark_pkt, scapy_pkt)

            pyshark_capture.close()
            logger.info(f"Finished reading packets from {self.pcap_path}")

        except Exception as exc:
            logger.error(f"Error reading pcap file {self.pcap_path}: {exc}")
            return
