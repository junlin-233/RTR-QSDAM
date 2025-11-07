#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
#
# 描述:
#   1. 散点图使用双对数变换和增强 Jittering，并移除文件名标注。
#   2. 核心逻辑：不排除任何在输入 CSV 中有记录的文件（即使加权得分为 0）。
#
# 依赖: matplotlib, numpy
#
# 用法: 
#   pip install matplotlib numpy
#   # 生成 PNG (默认, 高清 400 DPI)
#   python3 your_script_name.py
#   # 生成 SVG 矢量图
#   python3 your_script_name.py --format svg
#

import csv
import os
import argparse
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

# --- 权重配置 ---
PERM_DEFENSE_WEIGHTS = {1: 1.0, 2: 0.8, 3: 0.5, 4: 0.2}
SYSCALL_RISK_WEIGHTS = {'HIGH': 1.0, 'MEDIUM': 0.5, 'LOW': 0.1}
SMOOTHING_ALPHA = 0.01 # 拉普拉斯平滑参数
HIGH_DPI = 400 

# 设置 CSV 字段大小限制
csv.field_size_limit(10 * 1024 * 1024)

# --- 1. 数据加载函数 (保持不变) ---

def load_permissions(csv_path):
    """加载 permissions_by_file.csv (使用 UTF-8)"""
    data = defaultdict(lambda: {'weighted_defense': 0.0, 'raw': 0})
    if not os.path.exists(csv_path): return None
        
    print(f"[*] 正在加载权限防御数据: {csv_path}")
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            for row in r:
                try:
                    file = row["file"]
                    api_type = int(row.get("api_type", 4)) 
                    count = int(row["count"])
                    weight = PERM_DEFENSE_WEIGHTS.get(api_type, 0.2)
                    data[file]['weighted_defense'] += count * weight
                    data[file]['raw'] += count
                except:
                    continue
    except UnicodeDecodeError:
         print(f"[!] 警告: {csv_path} 编码错误。请确认输入文件编码是否为 UTF-8。")
         return None
    return data

def load_syscalls(csv_path):
    """加载 syscalls_by_file.csv (使用 UTF-8)"""
    data = defaultdict(lambda: {'weighted_risk': 0.0, 'raw': 0})
    if not os.path.exists(csv_path): return None
        
    print(f"[*] 正在加载系统调用风险数据: {csv_path}")
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            for row in r:
                try:
                    file = row["file"]
                    confidence = row.get("confidence", "LOW").upper()
                    count = int(row["count"])
                    weight = SYSCALL_RISK_WEIGHTS.get(confidence, 0.1)
                    data[file]['weighted_risk'] += count * weight
                    data[file]['raw'] += count
                except:
                    continue
    except UnicodeDecodeError:
         print(f"[!] 警告: {csv_path} 编码错误。请确认输入文件编码是否为 UTF-8。")
         return None
    return data

# --- 2. 核心概率计算  ---

def calculate_defense_capability_smooth(perm_data, sysc_data, alpha):
    """计算基于平滑 RTR 的文件级别概率。"""
    results = []
    all_files = set(perm_data.keys()) | set(sysc_data.keys())

    for file in all_files:
        perm_weighted = perm_data.get(file, {}).get('weighted_defense', 0.0)
        sysc_weighted = sysc_data.get(file, {}).get('weighted_risk', 0.0)
        perm_raw = perm_data.get(file, {}).get('raw', 0)
        sysc_raw = sysc_data.get(file, {}).get('raw', 0)
        if perm_raw == 0 and sysc_raw == 0:
            # 这种情况不应该发生，因为文件至少在 syscalls 或 permissions 文件中出现过
            continue 
            
        # 区分零分情况 
        if sysc_weighted == 0.0 and perm_weighted > 0.0:
            # 文件无有效风险暴露（sysc=0, perm>0）
            probability = 100.0
            rtr_smooth = 99999.0 
            triage_msg = "文件无有效风险暴露，防御能力评估为完美。"
        elif perm_weighted == 0.0 and sysc_weighted > 0.0:
            # 文件缺乏有效防御API（perm=0, sysc>0）
            probability = 0.0
            rtr_smooth = 0.0
            triage_msg = "文件缺乏有效防御API，防御能力评估为零。"
        elif perm_weighted == 0.0 and sysc_weighted == 0.0:
             # 加权得分为 0，但原始计数 > 0 的情况（权重配置导致）
             probability = 50.0 
             rtr_smooth = 1.0
             triage_msg = "防御/风险加权指标均为零，评估为中等（无证据）。"
        else:
            # 正常平滑 RTR 计算 (perm > 0, sysc > 0)
            perm_smooth = perm_weighted + alpha
            sysc_smooth = sysc_weighted + alpha
            rtr_smooth = perm_smooth / sysc_smooth
            
            # Sigmoid 归一化: P(Checked) = RTR / (1 + RTR) * 100%
            probability = (rtr_smooth / (1 + rtr_smooth)) * 100.0
            
            # 风险评估总结
            if probability > 95:
                 triage_msg = "防御能力极强，安全性高。"
            elif probability < 5:
                 triage_msg = "风险暴露远超防御能力，文件安全性低。"
            else:
                 triage_msg = "防御与风险处于平衡或中等水平。"


        results.append({
            'file': file,
            'perm_raw_count': perm_raw,
            'syscall_raw_count': sysc_raw,
            'weighted_defense_score': perm_weighted, 
            'weighted_risk_score': sysc_weighted,   
            'risk_triage_ratio_RTR': rtr_smooth,
            'probability_percent': probability,
            'triage_summary': triage_msg
        })

    return results



# --- 3. 可视化函数：散点图函数  ---

def plot_scatter_chart(results, output_path, output_format='png'):
    # 解决中文乱码问题
    plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'WenQuanYi Zen Hei', 'DejaVu Sans']
    plt.rcParams['axes.unicode_minus'] = False 
    
    # 提取数据
    defense_scores = np.array([d['weighted_defense_score'] for d in results])
    risk_scores = np.array([d['weighted_risk_score'] for d in results])
    probabilities = np.array([d['probability_percent'] for d in results])

    # 双对数变换
    def loglog_transform(x):
        return np.log2(np.log2(x + 1) + 1)

    loglog_risk = loglog_transform(risk_scores)
    loglog_defense = loglog_transform(defense_scores)
    
    # 增强 Jittering
    JITTER_STRENGTH = 0.35 
    jitter_x = np.random.uniform(-JITTER_STRENGTH, JITTER_STRENGTH, len(loglog_risk))
    jitter_y = np.random.uniform(-JITTER_STRENGTH, JITTER_STRENGTH, len(loglog_defense))
    
    final_x = np.maximum(loglog_risk + jitter_x, 0.01)
    final_y = np.maximum(loglog_defense + jitter_y, 0.01)

    # 绘图
    cmap = plt.cm.RdYlGn_r 
    scatter_size = np.cbrt(risk_scores + 1) * 15 

    fig, ax = plt.subplots(figsize=(14, 12)) 
    scatter = ax.scatter(final_x, final_y, 
                          c=probabilities, 
                          cmap=cmap, 
                          s=scatter_size,
                          alpha=0.4,
                          edgecolors='k', 
                          linewidth=0.1)

    cbar = fig.colorbar(scatter)
    cbar.set_label('系统调用被权限检查覆盖的概率 (%)', rotation=270, labelpad=20, fontsize=12)
    
    max_val = max(final_x.max(), final_y.max()) * 1.05 
    ax.plot([0, max_val], [0, max_val], 'k--', alpha=0.5, label='RTR = 1 (防御平衡线)')
    
    ax.set_xlabel('风险暴露得分 (Weighted Risk Score) [LogLog 变换 + Jitter]', fontsize=14)
    ax.set_ylabel('防御能力得分 (Weighted Defense Score) [LogLog 变换 + Jitter]', fontsize=14)
    ax.set_title('文件安全状态评估：防御能力 vs 风险暴露 ', fontsize=16)
    ax.legend(fontsize=12)
    ax.grid(True, linestyle='--', alpha=0.6)

    # 保存图表 
    scatter_output_file = f"defense_assessment_scatter.{output_format}"
    if output_format == 'svg':
        plt.savefig(scatter_output_file, format='svg')
    else: 
        plt.savefig(scatter_output_file, dpi=HIGH_DPI) 
    
    print(f"[***] 成功生成高清散点分布图：{scatter_output_file} (DPI: {HIGH_DPI})")
    plt.close(fig) # 关闭散点图


# --- 5. 主程序  ---

def main():
    parser = argparse.ArgumentParser(description="使用平滑评估模型计算文件防御能力并可视化。")
    parser.add_argument("--perm", default="permissions_by_file.csv", help="权限扫描输出 CSV 文件名。")
    parser.add_argument("--sysc", default="syscalls_by_file.csv", help="系统调用扫描输出 CSV 文件名。")
    parser.add_argument("--format", default="png", choices=['png', 'svg'], 
                        help="输出图片格式：'png' (默认，高清 400 DPI) 或 'svg' (矢量图)。")
    args = parser.parse_args()

    perm_data = load_permissions(args.perm)
    sysc_data = load_syscalls(args.sysc)
    
    if perm_data is None or sysc_data is None:
        print("[!] 错误: 缺少必要的 CSV 文件，或文件编码解析失败。请检查输入文件。")
        return
        
    final_results = calculate_defense_capability_smooth(perm_data, sysc_data, SMOOTHING_ALPHA)

    # 导出 CSV
    output_csv = "defense_assessment.csv"
    print(f"\n[*] 正在将 {len(final_results)} 条结果写入到 {output_csv}")
    
    with open(output_csv, "w", newline="", encoding="utf-8-sig") as f: 
        fieldnames = ['file', 'perm_raw_count', 'syscall_raw_count', 'weighted_defense_score', 
                      'weighted_risk_score', 'risk_triage_ratio_RTR', 'probability_percent', 'triage_summary']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        rows_to_write = []
        for row in final_results:
             rows_to_write.append({
                'file': row['file'],
                'perm_raw_count': row['perm_raw_count'],
                'syscall_raw_count': row['syscall_raw_count'],
                'weighted_defense_score': f"{row['weighted_defense_score']:.2f}",
                'weighted_risk_score': f"{row['weighted_risk_score']:.2f}",
                'risk_triage_ratio_RTR': f"{row['risk_triage_ratio_RTR']:.4f}",
                'probability_percent': f"{row['probability_percent']:.2f}%",
                'triage_summary': row['triage_summary']
            })
        writer.writerows(rows_to_write)
    print(f"[*] 成功！请查看 {output_csv} 文件。")

    # 执行可视化（仅保存，不弹出窗口，避免服务端阻塞）
    plot_scatter_chart(final_results, "defense_assessment_scatter", output_format=args.format)

if __name__ == "__main__":
    main()
