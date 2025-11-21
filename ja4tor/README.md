# Dependence
pip install pyshark numpy pandas

# Debian/Ubuntu
sudo apt install tshark

# macOS
brew install wireshark
sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)

2. project structure
/
│
├── core/
│   ├── __init__.py
│   └── flow_reassembler.py
│
├── features/
│   ├── __init__.py
│   ├── performance.py
│   ├── transport.py
│   ├── security.py
│   └── application.py
│
├── tools/
│   └── __init__.py
│
├── main.py
├── requirements.txt
└── config/
    └── settings.yaml

3. command
python main.py --pcap /path/to/input.pcap --out /path/to/output.csv