import csv
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent / 'data'

def load_defense_csv(path: Path):
    items = []
    if not path.exists():
        return items
    with open(path, newline='', encoding='utf-8-sig') as f:
        r = csv.DictReader(f)
        for row in r:
            # probability_percent 可能带 %
            prob_raw = str(row.get('probability_percent', '0')).strip().rstrip('%')
            try:
                prob = float(prob_raw)
            except Exception:
                prob = 0.0
            items.append({
                'file': row.get('file',''),
                'perm_raw_count': float(row.get('perm_raw_count', 0) or 0),
                'syscall_raw_count': float(row.get('syscall_raw_count', 0) or 0),
                'weighted_defense_score': float(row.get('weighted_defense_score', 0) or 0),
                'weighted_risk_score': float(row.get('weighted_risk_score', 0) or 0),
                'risk_triage_ratio_RTR': float(row.get('risk_triage_ratio_RTR', 0) or 0),
                'probability_percent': prob,
                'triage_summary': row.get('triage_summary','')
            })
    return items

def grade(prob: float) -> str:
    if prob >= 95:
        return 'A (安全)'
    if prob >= 80:
        return 'B (较安全)'
    if prob >= 60:
        return 'C (一般)'
    if prob >= 30:
        return 'D (偏风险)'
    return 'E (高风险)'

def generate_report():
    data = load_defense_csv(BASE_DIR / 'defense_assessment.csv')
    # 总览
    if not data:
        summary = {
            'overview': '未找到 defense_assessment.csv，无法生成报告',
            'files': []
        }
    else:
        total = len(data)
        avg_prob = sum(d['probability_percent'] for d in data) / total if total else 0.0
        by_grade = {'A':0,'B':0,'C':0,'D':0,'E':0}
        for d in data:
            g = grade(d['probability_percent'])[0]
            by_grade[g] += 1
        summary = {
            'overview': f'共评估 {total} 个文件，平均覆盖概率 {avg_prob:.2f}%。',
            'grade_distribution': by_grade,
            'files': [
                {
                    'file': d['file'],
                    'probability_percent': d['probability_percent'],
                    'grade': grade(d['probability_percent']),
                    'rtr': d['risk_triage_ratio_RTR'],
                    'triage_summary': d['triage_summary']
                } for d in sorted(data, key=lambda x: x['probability_percent'])
            ]
        }

    # 保存 JSON 和 文本
    # 计算总体等级（使用平均概率）
    avg_prob = 0.0
    if summary.get('files'):
        avg_prob = sum(f['probability_percent'] for f in summary['files']) / len(summary['files'])
    overall_grade = grade(avg_prob)
    summary['overall_grade'] = overall_grade
    summary['overall_probability'] = avg_prob

    (BASE_DIR / 'security_report.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')

    lines = []
    if 'overview' in summary:
        lines.append(summary['overview'])
    if 'grade_distribution' in summary:
        dist = summary['grade_distribution']
        lines.append(f"等级分布：A={dist.get('A',0)}, B={dist.get('B',0)}, C={dist.get('C',0)}, D={dist.get('D',0)}, E={dist.get('E',0)}")
    lines.append('')
    lines.append(f"总体等级：{summary.get('overall_grade','N/A')} (平均覆盖概率 {avg_prob:.2f}%)")
    lines.append('')
    lines.append('明细（按安全性由低到高排序）：')
    for f in summary.get('files', []):
        lines.append(f"- {f['file']} | 覆盖概率 {f['probability_percent']:.2f}% | 等级 {f['grade']} | RTR {f['rtr']:.4f} | {f['triage_summary']}")

    (BASE_DIR / 'security_report.txt').write_text('\n'.join(lines), encoding='utf-8')

if __name__ == '__main__':
    generate_report()


