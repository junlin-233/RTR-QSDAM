import os
import csv
import sys
from elftools.elf.elffile import ELFFile
from collections import Counter
import matplotlib.pyplot as plt
import argparse

# 权限 API 列表及其类型 (Type: 1-4)
KNOWN_PERMISSION_APIS = {
    "checkPermission": 1,
    "checkCallingPermission": 2,
    "checkCallingOrSelfPermission": 2,
    "checkSelfPermission": 1,
    "enforcePermission": 1,
    "enforceCallingPermission": 2,
    "enforceCallingOrSelfPermission": 2,
    "sendBroadcast": 3,
    "sendOrderedBroadcast": 3,
    "registerReceiver": 4,
    "checkComponentPermission": 2,
    "broadcastIntentLocked": 3,
    "isPermissionEnforced": 2,
    "isPermissionEnforcedLocked": 2,
    "send": 3,
    "requestPermissions": 4,
    "grantRuntimePermission": 1,
    "revokeRuntimePermission": 1,
    "noteOp": 1,
    "noteOpNoThrow": 1,
    "checkOp": 1,
    "checkOpNoThrow": 1,
    "checkUidPermission": 1,
    "checkSignatures": 1,
    "verifyPermission": 1,
    "requestPermission": 2,
    "enforceCallingPermission": 2,
    "requestPermissionsFromUser": 3,
    "requestRuntimePermissions": 1,
    "permissionCheck": 2
}

def is_elf(path):
    """检测文件是否为 ELF 格式"""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False

def scan_imports_with_pyelftools(path):
    """使用 pyelftools 扫描 ELF 动态符号表，查找已知的权限 API"""
    apis_found = []
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            # 遍历节区以找到动态符号表
            for section in elf.iter_sections():
                if section.name == ".dynsym":
                    for sym in section.iter_symbols():
                        name = sym.name
                        # 检查是否匹配已知的 API
                        for api in KNOWN_PERMISSION_APIS:
                            # 使用简单的子字符串检查
                            if api in name:
                                apis_found.append(api)
    except Exception as e:
        print(f"[!] 解析 {path} 出错: {e}")
    return apis_found

def analyze_file(path):
    """分析文件并查找权限相关的 API"""
    results = []
    # 键: (api, api_type), 值: 计数
    counts = {}

    # 1) 基于字符串匹配查找权限 API (适用于所有文件类型，但方式比较粗略)
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read()
            for api, api_type in KNOWN_PERMISSION_APIS.items():
                c = content.count(api)
                if c > 0:
                    counts[(api, api_type)] = counts.get((api, api_type), 0) + c
    except Exception:
        pass

    # 2) 如果是 ELF 文件，解析导入表 (对导入的函数更精确)
    if is_elf(path):
        apis = scan_imports_with_pyelftools(path)
        for api in apis:
            api_type = KNOWN_PERMISSION_APIS.get(api, "unknown")
            counts[(api, api_type)] = counts.get((api, api_type), 0) + 1

    for (api, api_type), count in counts.items():
        results.append((api, api_type, count))

    return results

# --- 可视化函数 ---

def visualize_top_api_counts(total_data, outdir='.', top_n=15):
    """生成 Top N API 计数柱状图"""
    if not total_data:
        print("[!] 没有数据可用于 Top API 计数的绘图。")
        return

    # total_data 是一个字典，键为 (api, api_type)，值为计数。
    # 我们按计数进行排序。
    # 转换为列表: [(api, count)]
    api_counts = sorted([(k[0], v) for k, v in total_data.items()], key=lambda item: item[1], reverse=True)
    
    top_results = api_counts[:top_n]
    apis = [item[0] for item in top_results]
    counts = [item[1] for item in top_results]

    plt.figure(figsize=(12, 8))
    plt.bar(apis, counts, color='darkblue')

    # 保持英文标签
    plt.xlabel('Permission API', fontsize=12)
    plt.ylabel('Total Count Across All Files', fontsize=12)
    plt.title(f'Top {top_n} Permission API Counts', fontsize=14)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    output_path = os.path.join(outdir, 'permissions_top_apis.png')
    plt.savefig(output_path)
    print(f"[+] Top API 计数图已保存至: {output_path}")

def visualize_api_type_distribution(total_data, outdir='.'):
    """生成 API 类型分布饼图"""
    if not total_data:
        print("[!] 没有数据可用于 API 类型分布的绘图。")
        return

    type_counts = Counter()
    
    for (api, api_type), count in total_data.items():
        # 确保 api_type 是整数或回退到字符串 'Unknown'
        type_label = f"Type {api_type}" if isinstance(api_type, int) else str(api_type)
        type_counts[type_label] += count

    labels = list(type_counts.keys())
    counts = list(type_counts.values())
    
    # 对标签进行排序，以保持颜色/切片顺序一致
    labels, counts = zip(*sorted(zip(labels, counts)))

    # 简单颜色列表
    colors = ['#FF9999', '#66B3FF', '#99FF99', '#FFCC99', '#C2C2F0', '#FFB3E6']
    
    plt.figure(figsize=(10, 10))
    # Autopct 格式化百分比
    plt.pie(counts, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors[:len(labels)],
            wedgeprops={'edgecolor': 'black', 'linewidth': 1})
    
    # 保持英文标签
    plt.title('Total Permission API Match Count by Type', fontsize=14)
    plt.tight_layout()

    output_path_pie = os.path.join(outdir, 'permissions_type_distribution.png')
    plt.savefig(output_path_pie)
    print(f"[+] API 类型分布图已保存至: {output_path_pie}")

# --- 主逻辑  ---

def main(folder):
    per_file = []
    # total 是一个字典，用于存储 (api, api_type) -> count
    total = {} 

    print(f"[*] 开始分析目录: {folder}")
    
    for root, _, files in os.walk(folder):
        for fname in files:
            fpath = os.path.join(root, fname)
            results = analyze_file(fpath)
            
            # 跳过没有匹配项的文件
            if not results:
                continue
                
            for api, api_type, count in results:
                # 1. 为逐文件 CSV 准备数据
                per_file.append((fpath, api, api_type, count))
                
                # 2. 累加总计字典的数据
                key = (api, api_type)
                total[key] = total.get(key, 0) + count

    # --- 保存 CSV 结果 ---
    
    # 输出逐文件结果
    with open("permissions_by_file.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["file", "api", "api_type", "count"])
        for row in per_file:
            w.writerow(row)

    # 输出总计结果
    with open("permissions_total.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["api", "api_type", "count"])
        # 对结果按计数排序，以确保 CSV 输出一致性
        for (api, api_type), count in sorted(total.items(), key=lambda item: item[1], reverse=True):
            w.writerow([api, api_type, count])

    # --- 生成可视化图表 ---
    visualize_top_api_counts(total)
    visualize_api_type_distribution(total)

    print("\n=== 汇总 ===")
    print(f"已分析文件数 (有匹配项): {len(set(p[0] for p in per_file))}")
    print(f"发现的独立 API 总数: {len(total)}")
    print("[+] CSV 输出: permissions_by_file.csv, permissions_total.csv")
    print("[+] 图像输出: permissions_top_apis.png, permissions_type_distribution.png")


if __name__ == "__main__":
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("错误: matplotlib 未安装。请运行 'pip install matplotlib' 安装。")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="权限 API 分析 (含 ELF 导入表) 及可视化")
    # 添加文件夹路径参数
    parser.add_argument("folder", help="输入待分析的目录")
    args = parser.parse_args()
    main(args.folder)
