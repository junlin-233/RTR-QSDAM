# RTR-QSDAM安全分析器
一款轻量级且自动化的**二进制文件安全分析工具**，专为嵌入式系统和汽车系统设计。

它评估权限检查和系统调用行为，随后量化**Risk-to-Defense Ratio**以提供全面的安全洞察。

--- 
## 功能 
-  **系统调用分析** — 检测二进制代码中的潜在风险暴露。 
-  **权限检查评估** — 量化防御机制。 
-  **安全可视化** — 生成散点图、柱状图和饼状图。 
-  **自动化报告生成** —— 生成TXT/JSON格式的摘要报告。 
-  **FastAPI 后端** — 实时进度追踪与异步任务调度。 
-  **静态前端** — 简单的用户界面用于触发操作和查看结果。 

| 文件                | 功能描述                                               |
| ------------------- | -------------------------------------------------- |
| **check.py**        | 从 ELF 文件中提取权限相关 API，统计调用次数并生成 CSV + 饼图 + 柱状图。      |
| **find_syscall.py** | 使用 Capstone 与 pyelftools 对 ELF 文件反汇编，提取系统调用与置信度分布。 |
| **link.py**         | 将前两者结果融合，计算 “风险防御比（RTR）” 并生成散点分布图。                 |
| **report.py**       | 综合生成安全性等级报告（JSON/TXT 格式）。                          |
| **main.py**         | FastAPI Web 服务：统一调度分析任务、跟踪进度、提供结果下载接口。             |
---
## 技术栈 
- **后端：** FastAPI，Python 3.9+ 
- **二进制分析：** pyelftools、capstone 
- **可视化工具：** matplotlib、numpy 
- **前端：** 静态HTML/JS + REST API
---
## 快速入门 

### 1. 克隆仓库 
git clone https://github.com/yourname/RTR-QSDAM.git 

进入RTR-QSDAM目录 

### 2. 安装依赖项 
pip install -r requirements.txt

### 3. 启动 FastAPI 服务器 
uvicorn main:app --reload

### 4. 打开浏览器 
访问 http://127.0.0.1:8000/static

---
