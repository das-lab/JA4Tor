import pandas as pd
import numpy as np
import ipaddress
import matplotlib.pyplot as plt
import seaborn as sns
import os
from scipy.spatial.distance import jensenshannon
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report


DATA_PATH = "data/test.csv"
ITERATIONS = 1       

def ip_to_int(ip_str):
    try:
        return int(ipaddress.ip_address(ip_str))
    except Exception:
        return 0


def preprocess_data(df: pd.DataFrame) -> pd.DataFrame:
    if 'Src IP' in df.columns:
        df['Src IP'] = df['Src IP'].apply(ip_to_int)
    if 'Dst IP' in df.columns:
        df['Dst IP'] = df['Dst IP'].apply(ip_to_int)

    cols_to_drop = ['Flow ID', 'Timestamp', 'Protocol']
    df = df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors='ignore')

    df = df.fillna(0)
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    return df


def calculate_jsd(feature_col: pd.Series, target_col: pd.Series, n_bins: int = 50) -> float:
    unique_labels = np.unique(target_col)
    if len(unique_labels) < 2:
        return 0.0
    min_val, max_val = feature_col.min(), feature_col.max()
    if min_val == max_val:
        return 0.0
    bins = np.linspace(min_val, max_val, n_bins + 1)
    distributions = []
    for label in unique_labels:
        subset = feature_col[target_col == label]
        hist, _ = np.histogram(subset, bins=bins, density=True)
        prob = hist + 1e-12
        distributions.append(prob / prob.sum())
    scores = []
    for i in range(len(distributions)):
        for j in range(i + 1, len(distributions)):
            scores.append(jensenshannon(distributions[i], distributions[j]))
    return float(np.mean(scores)) if scores else 0.0


def select_features_jsd(X: pd.DataFrame, y: pd.Series):
    jsd_scores = {}
    for col in X.columns:
        jsd_scores[col] = calculate_jsd(X[col], y)
    sorted_features = sorted(jsd_scores.items(), key=lambda item: item[1], reverse=True)

    if not sorted_features:
        return []

    selected_feats = [f[0] for f in sorted_features[:5]]

    if len(sorted_features) > 5:
        for i in range(5, len(sorted_features)):
            current_score = sorted_features[i][1]
            prev_score = sorted_features[i - 1][1]

            if current_score > 0.5 * prev_score:
                break
            else:
                selected_feats.append(sorted_features[i][0])

    return selected_feats


def get_stratified_split(origin_df: pd.DataFrame, train_size: int = 4000, test_size: int = 1000):
    train_dfs = []
    test_dfs = []
    for label, group in origin_df.groupby('traffic_type'):
        if len(group) < (train_size + test_size):
            replace_flag = True
        else:
            replace_flag = False

        test_sample = group.sample(n=test_size, replace=replace_flag)
        if replace_flag:
            train_sample = group.sample(n=train_size, replace=True)
        else:
            remaining = group.drop(test_sample.index)
            train_sample = remaining.sample(n=train_size, replace=False)

        train_dfs.append(train_sample)
        test_dfs.append(test_sample)

    train_df = pd.concat(train_dfs).sample(frac=1).reset_index(drop=True)
    test_df = pd.concat(test_dfs).sample(frac=1).reset_index(drop=True)
    return train_df, test_df


def train_predict_pipeline(X_train: pd.DataFrame, y_train: pd.Series,
                           X_test: pd.DataFrame, y_test: pd.Series):
    y_train_l1 = y_train.apply(lambda x: 0 if x == 0 else 1)
    l1_feats = select_features_jsd(X_train, y_train_l1)

    mask_l2 = y_train != 0
    X_train_l2_data = X_train[mask_l2]
    y_train_l2 = y_train[mask_l2].apply(lambda x: 1 if x == 1 else 2)
    l2_feats = select_features_jsd(X_train_l2_data, y_train_l2)

    mask_l3 = y_train.isin([2, 3, 4])
    X_train_l3_data = X_train[mask_l3]
    y_train_l3 = y_train[mask_l3]
    l3_feats = select_features_jsd(X_train_l3_data, y_train_l3)

    final_feature_set = list(set(l1_feats + l2_feats + l3_feats))
    if not final_feature_set:
        final_feature_set = list(X_train.columns)

    rf_l1 = RandomForestClassifier(n_estimators=100, n_jobs=-1)
    rf_l1.fit(X_train[final_feature_set], y_train_l1)

    rf_l2 = RandomForestClassifier(n_estimators=100, n_jobs=-1)
    rf_l2.fit(X_train_l2_data[final_feature_set], y_train_l2)

    rf_l3 = RandomForestClassifier(n_estimators=100, n_jobs=-1)
    rf_l3.fit(X_train_l3_data[final_feature_set], y_train_l3)

    final_preds = pd.Series(0, index=X_test.index, dtype=int)
    X_test_filtered = X_test[final_feature_set]

    pred_l1 = rf_l1.predict(X_test_filtered)
    malicious_idx = X_test.index[pred_l1 == 1]

    if len(malicious_idx) > 0:
        X_test_l2 = X_test_filtered.loc[malicious_idx]
        pred_l2 = rf_l2.predict(X_test_l2)

        l2_series = pd.Series(pred_l2, index=malicious_idx)
        tor_idx = l2_series[l2_series == 1].index
        final_preds.loc[tor_idx] = 1

        encap_idx = l2_series[l2_series == 2].index
        if len(encap_idx) > 0:
            X_test_l3 = X_test_filtered.loc[encap_idx]
            pred_l3 = rf_l3.predict(X_test_l3)
            final_preds.loc[encap_idx] = pred_l3

    imps = {}
    for name, model in zip(['L1', 'L2', 'L3'], [rf_l1, rf_l2, rf_l3]):
        imp_series = pd.Series(model.feature_importances_, index=final_feature_set)
        if name == 'L1':
            n_samples = len(X_train)
        elif name == 'L2':
            n_samples = len(X_train_l2_data)
        else:
            n_samples = len(X_train_l3_data)
        imps[name] = (imp_series, n_samples)

    return final_preds, imps


if __name__ == "__main__":
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"DATA_PATH ERROR:{DATA_PATH}")

    origin_df = pd.read_csv(DATA_PATH)
    if 'traffic_type' not in origin_df.columns:
        raise ValueError("No 'traffic_type'")

    print(f"Loaded dataset from {DATA_PATH}, shape = {origin_df.shape}")

    metrics_history = {'accuracy': [], 'precision': [], 'recall': [], 'f1': []}
    hwfi_accumulator = pd.DataFrame()
    layer_imp_accumulator = {'L1': pd.DataFrame(), 'L2': pd.DataFrame(), 'L3': pd.DataFrame()}

    print(f"Starting {ITERATIONS} iterations on cleaned CSV...")

    for i in range(ITERATIONS):
        print(f"\nIteration {i + 1}/{ITERATIONS}...")
        train_df, test_df = get_stratified_split(origin_df)

        y_train = train_df['traffic_type']
        X_train = preprocess_data(train_df.drop('traffic_type', axis=1))
        y_test = test_df['traffic_type']
        X_test = preprocess_data(test_df.drop('traffic_type', axis=1))

        common_cols = X_train.columns.intersection(X_test.columns)
        X_train = X_train[common_cols]
        X_test = X_test[common_cols]

        preds, importances_data = train_predict_pipeline(X_train, y_train, X_test, y_test)

        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds, average='weighted', zero_division=0)
        rec = recall_score(y_test, preds, average='weighted', zero_division=0)
        f1 = f1_score(y_test, preds, average='weighted', zero_division=0)

        metrics_history['accuracy'].append(acc)
        metrics_history['precision'].append(prec)
        metrics_history['recall'].append(rec)
        metrics_history['f1'].append(f1)

        all_feats = X_train.columns
        iter_hwfi = pd.Series(0.0, index=all_feats)
        total_n = len(X_train)

        for layer_name, (imp_series, n_samples) in importances_data.items():
            aligned = imp_series.reindex(all_feats).fillna(0)

            if layer_imp_accumulator[layer_name].empty:
                layer_imp_accumulator[layer_name] = aligned.to_frame(name='imp')
            else:
                layer_imp_accumulator[layer_name] = layer_imp_accumulator[layer_name].add(
                    aligned.to_frame(name='imp'),
                    fill_value=0,
                )

            weight = n_samples / total_n if total_n > 0 else 0.0
            iter_hwfi += aligned * weight

        if hwfi_accumulator.empty:
            hwfi_accumulator = iter_hwfi.to_frame(name='HWFI')
        else:
            hwfi_accumulator = hwfi_accumulator.add(iter_hwfi.to_frame(name='HWFI'), fill_value=0)

    final_hwfi = hwfi_accumulator / ITERATIONS
    for k in layer_imp_accumulator:
        layer_imp_accumulator[k] /= ITERATIONS

    final_hwfi = final_hwfi[final_hwfi['HWFI'] > 0]
    final_hwfi = final_hwfi.sort_values('HWFI', ascending=False).head(20)

    for k in layer_imp_accumulator:
        layer_imp_accumulator[k] = layer_imp_accumulator[k][layer_imp_accumulator[k]['imp'] > 0]

    print("\n" + "=" * 40)
    print("Average Metrics on cleaned CSV:")
    print(f"Accuracy:  {np.mean(metrics_history['accuracy']):.4f}")
    print(f"Precision: {np.mean(metrics_history['precision']):.4f}")
    print(f"Recall:    {np.mean(metrics_history['recall']):.4f}")
    print(f"F1-Score:  {np.mean(metrics_history['f1']):.4f}")
    print("=" * 40)

    target_names = ['Normal', 'Tor', 'Tor_SS', 'Tor_Trojan', 'Tor_VMess']
    print("\nClassification Report (Last Iteration):")
    print(classification_report(y_test, preds, target_names=target_names, digits=4))
