## JA4Tor Self-Built Dataset

The specific collection details of our Self-Built dataset used in our paper are as follows. 

| #    | Traffic Type Description                                 | pcap Count | Size   |
| ---- | -------------------------------------------------------- | ---------- | ------ |
| 1    | Clearnet traffic                                         | 4248       | 20.6GB |
| 2    | Darknet traffic + Tor (with obfs4) - V2Ray               | 1333       | 6.12GB |
| 3    | Darknet traffic + Tor (with obfs4) + V2Ray + Trojan      | 761        | 3.92GB |
| 4    | Darknet traffic + Tor (with obfs4) + V2Ray + ShadowSocks | 1560       | 7.47GB |
| 5    | Darknet traffic + Tor (with obfs4) + V2Ray + Vmess       | 1120       | 3.79GB |

The complete raw pcap files will be made publicly available in this repository upon paper acceptance. For now, we provide the traffic feature training and test sets derived after processing with JA4Tor.