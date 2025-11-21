import argparse
from core.pcap_reader import PcapReader
from core.flow_reassembler import FlowReassembler
from features.feature_merger import FeatureMerger
from writer import CSVWriter
from logger import logger
import os
import pdb

def main():
    parser = argparse.ArgumentParser(description="Fusion Flow Extractor")
    parser.add_argument("pcap_path", help="Path to the pcap file or directory")
    parser.add_argument("output_csv", help="Path to the output CSV file")
    parser.add_argument("--timeout", type=int, default=30, help="Flow timeout in seconds")
    args = parser.parse_args()

    if os.path.isfile(args.pcap_path):
        pcap_files = [args.pcap_path]
    elif os.path.isdir(args.pcap_path):
        pcap_files = [os.path.join(args.pcap_path, f) for f in os.listdir(args.pcap_path) if f.endswith(('.pcap', '.pcapng'))]
    else:
        logger.error(f"Invalid pcap path: {args.pcap_path}")
        return

    writer = CSVWriter(args.output_csv)
    merger = FeatureMerger()
    
    writer.write_row(merger.get_feature_names())
    
    total_flows_processed = 0

    try:
        for pcap_file in pcap_files:
            logger.info(f"Processing pcap file: {pcap_file}")
            reader = PcapReader(pcap_file)
            reassembler = FlowReassembler(timeout=args.timeout)
            
            for i, packet_tuple in enumerate(reader.read_packets()):
                if not packet_tuple:
                    continue
                expired_flows = reassembler.process_packet(packet_tuple)
                if expired_flows:
                    for flow in expired_flows:
                        features = merger.merge_features(flow)
                        writer.write_row(list(features.values()))
                        total_flows_processed += 1
                
                if (i + 1) % 1000 == 0:
                    logger.info(f"Processed {i + 1} packets, extracted {total_flows_processed} flows...")

            remaining_flows = reassembler.flush_all_flows()
            for flow in remaining_flows:
                features = merger.merge_features(flow)
                writer.write_row(list(features.values()))
                total_flows_processed += 1
                
            logger.info(f"Finished processing {pcap_file}. Total flows extracted so far: {total_flows_processed}")

    finally:
        writer.close()
        logger.info(f"All pcap files processed. Total flows extracted: {total_flows_processed}")
        logger.info(f"Output saved to {args.output_csv}")


if __name__ == "__main__":
    main()