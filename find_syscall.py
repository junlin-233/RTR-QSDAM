#!/usr/bin/env python3
# find_syscall_strings_with_xref.py
# 用途：在二进制（ELF .so/.bin）中通过字符串 + 符号表 + 反汇编交叉识别 API（例如系统调用或 libc API）
# 输出: syscalls_by_file.csv, syscalls_total.csv, syscall_scores.png, syscall_confidence_distribution.png
# 说明：置信度分为 HIGH / MEDIUM / LOW

import os, sys, re, csv
from collections import Counter, defaultdict
from elftools.elf.elffile import ELFFile
from capstone import *
import matplotlib.pyplot as plt

MIN_STR_LEN = 4
KEYWORDS = [
    "read", "write", "open", "openat", "close", "mmap", "munmap", "brk", "futex", "ioctl",
    "socket", "connect", "accept", "send", "recv", "sendto", "recvfrom", "bind", "listen",
    "execve", "clone", "fork", "exit", "exit_group", 
    "set_tid", "setpgid", "getpid", "getppid", "exit_group", "arch_prctl", "personality", 
    "wait4", "waitpid", "setuid", "setgid", "setresuid", "setresgid", "getuid", "geteuid", 
    "getgid", "getegid", "getgroups", "setgroups", "getpgrp", "setsid", "gettid", "tgkill",
    "madvise", "mprotect", "select", "poll", "io_submit", "io_getevents", "mmap", "mremap", 
    "mlock", "mlockall", "munlock", "munlockall", "msync", "remap_file_pages", "madvise",
    "fstat", "stat", "lstat", "statx", "fcntl", "flock", "fcntl64", "pipe", "pipe2", "socketpair",
    "sendmsg", "recvmsg", "sendto", "recvfrom", "getsockname", "getpeername", "bind", "listen",
    "accept", "connect", "setsockopt", "getsockopt", "shutdown", "sendfile", "pread64", "pwrite64",
    "gettimeofday", "settimeofday", "time", "clock_gettime", "clock_settime", "clock_getres", 
    "timer_create", "timer_delete", "timer_settime", "timer_gettime", "timer_getoverrun", "nanosleep",
    "rename", "link", "unlink", "mkdir", "rmdir", "chmod", "chown", "statfs", "fstatfs", "utimes",
    "kill", "signal", "sigaction", "sigprocmask", "sigpending", "sigsuspend", "sigwaitinfo",
    "sigtimedwait", "rt_sigaction", "rt_sigprocmask", "rt_sigpending", "rt_sigsuspend", 
    "rt_sigtimedwait", "ioctl", "futex", "setrlimit", "getrlimit", "getrusage", "gettimeofday", 
    "settimeofday", "time", "clock_gettime", "clock_settime", "clock_getres", "getuid", "geteuid", 
    "getgid", "getegid", "getgroups", "setgroups", "setuid", "setgid", "setresuid", "setresgid", 
    "getpgrp", "setsid", "setpgid", "getppid", "getpgrp", "tgkill", "kill", "signal", "sigaction", 
    "sigprocmask", "sigpending", "sigsuspend", "sigwaitinfo", "sigtimedwait", "rt_sigaction", 
    "rt_sigprocmask", "rt_sigpending", "rt_sigsuspend", "rt_sigtimedwait", "ioctl", "fcntl", "flock", 
    "fcntl64", "pipe", "pipe2", "socketpair", "sendmsg", "recvmsg", "sendto", "recvfrom", "getsockname", 
    "getpeername", "socket", "bind", "listen", "accept", "connect", "setsockopt", "getsockopt", 
    "shutdown", "sendfile", "sendmsg", "recvmsg", "pread64", "pwrite64", "mmap", "mprotect", "munmap", 
    "msync", "madvise", "remap_file_pages", "mremap", "mlock", "mlockall", "munlock", "munlockall"
]

KW_SET = set(k.lower() for k in KEYWORDS)
KW_RE = re.compile(r'(?<![A-Za-z0-9_])(' + r'|'.join(re.escape(k) for k in KEYWORDS) + r')(?![A-Za-z0-9_])', re.I)

# ---------- 助手函数: 提取带有虚拟地址(VA)的字符串 ----------
def extract_strings_with_va(path, min_len=MIN_STR_LEN):
    """从 ELF 文件中提取可打印字符串及其虚拟地址 (VA)。"""
    res = []
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if not hasattr(sec, "data"):
                    continue
                name = sec.name
                # 关注可包含字符串的节
                if name in ('.rodata', '.rodata1', '.data', '.dynstr', '.strtab', '.rodata.rel.ro'):
                    data = sec.data()
                    base = sec['sh_addr']
                    cur = []
                    cur_off = None
                    for i, b in enumerate(data):
                        if 32 <= b <= 126:
                            if cur_off is None:
                                cur_off = i
                            cur.append(chr(b))
                        else:
                            if cur and len(cur) >= min_len:
                                s = ''.join(cur)
                                va = base + cur_off
                                res.append((va, s))
                            cur = []
                            cur_off = None
                    if cur and len(cur) >= min_len:
                        s = ''.join(cur)
                        va = base + (cur_off or 0)
                        res.append((va, s))
    except Exception:
        pass
    return res

# ---------- 助手函数: 收集动态符号 (dynsym) 和 GOT/PLT 映射 ----------
def gather_dynsym_got_plt(path):
    """收集动态符号表中的名称以及 GOT/PLT 中重定位的符号映射。"""
    names = set()
    got_map = {}
    plt_map = {}
    try:
        with open(path,'rb') as f:
            elf = ELFFile(f)
            dyn = elf.get_section_by_name('.dynsym')
            if dyn:
                for sym in dyn.iter_symbols():
                    if sym.name:
                        names.add(sym.name)
            rel = elf.get_section_by_name('.rela.plt') or elf.get_section_by_name('.rel.plt')
            if rel and dyn:
                for i, r in enumerate(rel.iter_relocations()):
                    symidx = r['r_info_sym']
                    symname = dyn.get_symbol(symidx).name if symidx < dyn.num_symbols() else None
                    if symname:
                        got_map[r['r_offset']] = symname
                # PLT 启发式映射
                pltsec = elf.get_section_by_name('.plt') or elf.get_section_by_name('.plt.got')
                if pltsec:
                    base = pltsec['sh_addr']
                    i = 0
                    for r in rel.iter_relocations():
                        symidx = r['r_info_sym']
                        symname = dyn.get_symbol(symidx).name if symidx < dyn.num_symbols() else None
                        if symname:
                            guessed = base + 16 + i * 16
                            plt_map[guessed] = symname
                            i += 1
    except Exception:
        pass
    return names, got_map, plt_map

# ---------- 助手函数: 反汇编 .text 节并定位引用 ----------
def get_text_insns(path):
    """反汇编 .text 节并返回指令列表和架构信息。"""
    try:
        with open(path,'rb') as f:
            elf = ELFFile(f)
            em = elf['e_machine']
            if em == 'EM_ARM':
                arch = 'arm'
                cs_arch, cs_mode = CS_ARCH_ARM, CS_MODE_ARM
            elif em == 'EM_AARCH64':
                arch = 'aarch64'
                cs_arch, cs_mode = CS_ARCH_ARM64, CS_MODE_ARM
            elif em == 'EM_386':
                arch = 'x86'
                cs_arch, cs_mode = CS_ARCH_X86, CS_MODE_32
            elif em == 'EM_X86_64':
                arch = 'x86_64'
                cs_arch, cs_mode = CS_ARCH_X86, CS_MODE_64
            else:
                return None, []

            sec = elf.get_section_by_name('.text')
            if not sec:
                return arch, []
            code = sec.data()
            base = sec['sh_addr']
            md = Cs(cs_arch, cs_mode)
            md.detail = False
            insns = list(md.disasm(code, base))
            return arch, insns
    except Exception:
        return None, []

def insn_references_va(insn, va, arch):
    """基本启发式：判断给定指令是否引用了内存地址 va。"""
    op = insn.op_str
    hex_nums = re.findall(r'0x[0-9a-fA-F]+', op)
    dec_nums = re.findall(r'(?<!0x)\b\d+\b', op)
    if arch in ('x86','x86_64'):
        if 'rip' in op or 'eip' in op:
            m = re.search(r'\[.*(rip|eip)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', op)
            if m:
                disp = int(m.group(2), 0)
                mem = insn.address + insn.size + disp
                if mem == va:
                    return True
        for h in hex_nums:
            if int(h,16) == va:
                return True
        for d in dec_nums:
            if int(d) == va:
                return True
    elif arch == 'arm':
        m = re.search(r'\[pc,\s*#(0x[0-9a-fA-F]+|\d+)\]', op)
        if m:
            imm = int(m.group(1),0)
            mem = insn.address + 8 + imm
            if mem == va:
                return True
        for h in hex_nums:
            if int(h,16) == va:
                return True
    elif arch == 'aarch64':
        for h in hex_nums:
            if int(h,16) == va:
                return True
        for d in dec_nums:
            if int(d) == va:
                return True
    return False

# ---------- 分析单个 ELF 文件 ----------
def analyze_file(path):
    """对单个 ELF 文件进行系统调用/API 匹配分析，并返回聚合结果。"""
    per_matches = []
    try:
        strs = extract_strings_with_va(path)
        dynsym, gotmap, pltmap = gather_dynsym_got_plt(path)
        arch, insns = get_text_insns(path)

        va_to_str = {}
        for va,s in strs:
            s_low = s.lower()
            va_to_str[va] = s

        # 1) 动态符号表命中 -> HIGH 置信度
        for sym in dynsym:
            s_low = sym.lower()
            for kw in KW_SET:
                if kw in s_low:
                    per_matches.append((kw, 'HIGH', f'dynsym:{sym}'))
        # 2) GOT/PLT 命中 -> HIGH 置信度
        for addr,sym in list(gotmap.items()) + list(pltmap.items()):
            s_low = sym.lower()
            for kw in KW_SET:
                if kw in s_low:
                    per_matches.append((kw, 'HIGH', f'got/plt:{sym}'))

        # 3) 字符串出现 => 检查代码引用
        if arch and insns:
            for va, s in va_to_str.items():
                s_low = s.lower()
                for kw in KW_SET:
                    if kw in s_low:
                        referenced = False
                        # 检查指令是否引用了该字符串的 VA
                        for ins in insns:
                            if insn_references_va(ins, va, arch):
                                referenced = True
                                break
                        if referenced:
                            # 字符串被代码引用 -> MEDIUM 置信度
                            per_matches.append((kw, 'MEDIUM', f'str-ref:{hex(va)}:"{s[:60]}"'))
                        else:
                            # 仅字符串出现 -> LOW 置信度
                            per_matches.append((kw, 'LOW', f'str-only:{hex(va)}:"{s[:60]}"'))
        else:
            # 无法反汇编: 将所有字符串命中视为 LOW 置信度
            for va,s in va_to_str.items():
                s_low = s.lower()
                for kw in KW_SET:
                    if kw in s_low:
                        per_matches.append((kw, 'LOW', f'str-only:{hex(va)}:"{s[:60]}"'))
    except Exception as e:
        # 打印错误但继续
        pass

    # 去重并计数: 每个关键词取最高置信度
    conf_rank = {'LOW':1, 'MEDIUM':2, 'HIGH':3}
    agg = {}
    for kw, conf, evidence in per_matches:
        if kw not in agg:
            agg[kw] = {'conf':conf, 'evidence':[evidence], 'count':1}
        else:
            # 如果发现更高的置信度，则更新
            if conf_rank[conf] > conf_rank[agg[kw]['conf']]:
                agg[kw]['conf'] = conf
            agg[kw]['evidence'].append(evidence)
            agg[kw]['count'] += 1
    return agg

# ---------- 扫描文件夹 ----------
def scan_folder(folder):
    """递归扫描文件夹中的 ELF 文件并汇总结果。"""
    per_file = {}
    total_score = Counter()
    for root, dirs, files in os.walk(folder):
        for fn in files:
            # 仅处理 .so, .bin 或无扩展名的文件 (简化判断)
            if not (fn.endswith('.so') or fn.endswith('.bin') or '.' not in fn):
                continue
            path = os.path.join(root, fn)
            agg = analyze_file(path)
            if not agg:
                continue
            per_file[path] = agg
            # 评分: HIGH += 10, MEDIUM += 5, LOW +=1
            for kw, info in agg.items():
                score = 10 if info['conf']=='HIGH' else (5 if info['conf']=='MEDIUM' else 1)
                total_score[kw] += score
    return per_file, total_score

# ---------- 保存输出结果 ----------
def save_results(per_file, total_score, outdir='.'):
    """将逐文件和总计结果保存为 CSV 文件。"""
    by_file_path = os.path.join(outdir,'syscalls_by_file.csv')
    total_path = os.path.join(outdir,'syscalls_total.csv')
    
    # 保存逐文件结果
    with open(by_file_path,'w',newline='',encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['file','keyword','confidence','count','evidences'])
        for path, agg in per_file.items():
            for kw, info in agg.items():
                w.writerow([path, kw, info['conf'], info['count'], " | ".join(info['evidence'])])
    
    # 保存总计得分结果
    with open(total_path,'w',newline='',encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['keyword','score'])
        for k,v in total_score.most_common():
            w.writerow([k,v])
            
    return by_file_path, total_path

# ---------- 可视化函数 (使用英文标签) ----------

def visualize_top_keywords(total_score, outdir='.', top_n=15):
    """生成 Top N 关键词得分柱状图 (英文标签)。"""
    if not total_score:
        print("[!] 没有数据可用于 Top 关键词的绘图。")
        return

    top_results = total_score.most_common(top_n)
    keywords = [item[0] for item in top_results]
    scores = [item[1] for item in top_results]

    plt.figure(figsize=(12, 8))
    plt.bar(keywords, scores, color='darkgreen')

    # 英文标签
    plt.xlabel('System Call/API Keyword', fontsize=12)
    plt.ylabel('Weighted Score (HIGH=10, MEDIUM=5, LOW=1)', fontsize=12)
    plt.title(f'Top {top_n} System Call/API Keyword Scores', fontsize=14)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    output_path = os.path.join(outdir, 'syscall_scores.png')
    plt.savefig(output_path)
    print(f"[+] Top 关键词得分图已保存至: {output_path}")

def visualize_confidence_distribution(per_file_data, outdir='.'):
    """生成总置信度分布柱状图 (英文标签)。"""
    if not per_file_data:
        print("[!] 没有数据可用于置信度分布的绘图。")
        return

    confidence_counts = Counter()
    for file_data in per_file_data.values():
        for info in file_data.values():
            # 正确的逻辑: 汇总所有条目的匹配次数，按其最高置信度级别分类
            confidence_counts[info['conf']] += info['count']

    # 确保固定的顺序
    labels = ['HIGH', 'MEDIUM', 'LOW']
    counts = [confidence_counts.get(l, 0) for l in labels]
    colors = ['#E55B5B', '#FFD700', '#64B5F6'] 

    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, counts, color=colors)

    # 英文标签
    plt.xlabel('Confidence Level', fontsize=12)
    plt.ylabel('Total Match Count', fontsize=12)
    plt.title('Total System Call/API Matches by Confidence Distribution', fontsize=14)

    # 在柱子上显示具体数字
    for bar in bars:
        height = bar.get_height()
        # 调整标签的 Y 轴位置
        y_pos = height + max(100, height * 0.05) if height > 0 else 500 
        plt.text(bar.get_x() + bar.get_width()/2., y_pos,
                f'{height}',
                ha='center', va='bottom', fontsize=11)
    
    # 调整 Y 轴限制
    if max(counts) > 0:
        plt.ylim(0, max(counts) * 1.15)

    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()

    output_path_conf = os.path.join(outdir, 'syscall_confidence_distribution.png')
    plt.savefig(output_path_conf)
    print(f"[+] 置信度分布图已保存至: {output_path_conf}")


# ---------- 主程序 ----------
def main():
    if len(sys.argv) < 2:
        print("用法: python3 find_syscall.py <文件或文件夹>")
        sys.exit(1)
    target = sys.argv[1]
    
    per_file = {}
    total = Counter()
    
    if os.path.isfile(target):
        if target.endswith('.csv'):
             print(f"错误: 目标 '{target}' 是一个 CSV 文件。请提供一个 ELF 二进制文件 (.so/.bin) 或一个文件夹。")
             sys.exit(1)
             
        agg = analyze_file(target)
        if agg:
            per_file[target] = agg
        for path,agg in per_file.items():
            for k,info in agg.items():
                score = 10 if info['conf']=='HIGH' else (5 if info['conf']=='MEDIUM' else 1)
                total[k] += score
    else:
        per_file, total = scan_folder(target)
        
    save_results(per_file, total)
    print("[+] CSV 输出: syscalls_by_file.csv, syscalls_total.csv")
    
    # 调用可视化函数
    visualize_top_keywords(total)
    visualize_confidence_distribution(per_file)

if __name__ == '__main__':
    # 简单的 matplotlib 导入检查
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("错误: matplotlib 未安装。请运行 'pip install matplotlib' 安装。")
        sys.exit(1)
        
    main()
