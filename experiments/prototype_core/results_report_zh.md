# Prototype-Core 实验结果与复现记录

## 1. 执行范围

- 远程独立目录：`/data1/zcx/ja4tor/experiments/prototype_core_20260712`。
- 原始 pcap 只读引用，没有复制、改名或覆盖；实验文件全部写入新目录。
- 五类原始 pcap 与融合特征 CSV 一一对应，共 9,022 组。
- 统一过滤后保留 7,542 个候选：NonTor 3,813、Tor 1,108、Tor-SS 1,085、Tor-Trojan 640、Tor-Vmess 896。
- 过滤条件为 pcap 0.5--20 MiB、CSV 至少四行、类别和路径完整；学习矩阵删除 IP、端口、时间戳、协议、域名和高基数哈希。

## 2. 选择规则与验证冻结

主实验先按 capture ID 的 SHA-256 顺序完成类内 70/10/20 划分，再用训练候选计算 P/T 特征 median/IQR 嵌入的类中位数和 MAD 尺度。各类、各分区内部按到本类原型的稳健距离升序选择，capture ID 用作固定并列规则。

Validation 比较每类 100、200、300 个 capture；因未达到 98.5% 目标，又按预案运行 400。最终冻结配置为：

```json
{
  "selected_budget": 200,
  "n_estimators": 300,
  "max_features": "0.5",
  "fusion_weight": 1.0,
  "validation_macro_f1_mean": 0.9504005641,
  "validation_seeds": [0, 1, 2, 3, 4],
  "selection_basis": "validation only",
  "test_opened": false
}
```

另行保留了“最近异类距离减本类距离”的判别式 margin 试验，其最佳 validation macro-F1 为 94.17%，低于主选择规则的 95.04%，因此没有用于测试集。该试验保存在远程 `run/margin/`，没有覆盖主结果。

## 3. 冻结测试结果

测试集仅在配置冻结后运行一次，模型随机种子为 0--9。每类测试输入平衡为 160 条 flow row，共包含 200 个互不交叉的测试 capture。

| 方法 | Accuracy (%) | Precision (%) | Recall (%) | Macro-F1 (%) |
|---|---:|---:|---:|---:|
| Logistic Regression | 86.50 | 88.16 | 86.50 | 86.83±0.00 |
| ExtraTrees | 92.66 | 92.79 | 92.66 | 92.69±0.19 |
| HistGradientBoosting | 94.00 | 93.96 | 94.00 | **93.98±0.00** |
| Hard Hierarchy | 93.71 | 93.76 | 93.71 | 93.73±0.25 |
| JA4Tor-H | 93.61 | 93.63 | 93.61 | 93.61±0.21 |
| JA4Tor-G | 93.77 | 93.78 | 93.77 | 93.77±0.17 |
| JA4Tor-DPF | 93.77 | 93.78 | 93.77 | 93.77±0.17 |

Validation 选择 `lambda=1`，因此 JA4Tor-DPF 与全局专家在冻结测试上重合。JA4Tor-DPF 与最强轻量基线相差 0.21 个百分点，未达到预设的 98.5% 绝对目标，也比“不超过 0.2 个百分点”的相对目标多 0.01 个百分点。测试结果没有用于重新选择样本、预算或超参数。

## 4. 划分稳定性

冻结模型配置在 split seeds 7、17、27、37、47 上各运行一次，DPF macro-F1 分别为 95.13%、93.78%、92.88%、95.25% 和 94.90%，均值与样本标准差为 94.39±1.02%。该波动大于固定划分上的模型种子波动，说明 capture 组成是当前结果的主要不确定性来源。

## 5. 结果文件与摘要哈希

本地结果位于 `experiments/prototype_core/results/final_v2/`，五个划分的完整 manifest、配置和 CSV 位于 `experiments/prototype_core/results/split_stability/`。

| 文件 | SHA-256 |
|---|---|
| `selection_candidates.csv` | `64de3a09adfaeef240dcd195ffb8de6850d6bd3f9f773f7f4eb219d0014afc0c` |
| `manifest_budget200_seed42.csv` | `4d3d6f9f3ae61e84b0cd5722f7a3cd5a09c8067b659eccdae894c4fb151696b9` |
| `frozen_config.json` | `12766eb9f07151a51d2b338de274124b9bb8c47e02f2c3b4340a3f2634fbde` |
| `summary.csv` | `4c40ec2818e77137c255e49d92a54eca7f087ca654533038fa9ebd87d6f53a8d` |
| `test_results.csv` | `3fb41096183061afbfb39a41a5283c059cfc7508c85bff1a1905ea3d63c9a535` |

manifest 的 train/validation/test capture ID 交集均为空，1,000 个选中 capture 均记录 pcap 和 CSV 的 SHA-256。

## 6. 图形与论文同步

以下图由同一组 `summary.csv`、`validation_search.csv`、逐类指标或预测产物生成：主比较、DPF 组件与 lambda sensitivity、capture budget、混淆矩阵、JSD 热力图、NonTor:Tor-family 比率、open-world、split stability 和 runtime--macro-F1。全部 PDF 使用正常色盲安全配色；为抵消 LaTeX 缩放，最终实验图采用 12/11/10.8 pt 的正文/刻度/图例与标注字号，并以接近单栏宽度的画布输出。Poppler 检查显示九张实验图均无嵌入栅格，逐张渲染检查未发现文字遮挡或裁切。

TeX 中所有活动的 `TrainPlaceholder` 和红色数值调用已移除。未测量的包级 shaping 只保留 `% TODO: packet-level replay required` 注释，不进入渲染正文。
