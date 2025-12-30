

---

# AiYue_Pro - 智能越权检测插件 (Smart IDOR Detector)

**AiYue_Pro** 是一款专为 Burp Suite 设计的高级被动扫描插件，旨在自动化检测 **越权漏洞 (IDOR / Broken Access Control)**。

它结合了**多账号并发重放**、**智能染色**和 **AI 大模型深度分析**技术，能够精准识别低权限或未授权账号是否能访问高敏感接口，极大降低了人工测试的成本和误报率。

---

## ✨ 核心功能 (Key Features)

* 🤖 **AI 智能分析 (AI-Powered Analysis)**
* 集成 主流LLM api（支持 GPT-4, Qwen/通义千问, DeepSeek 等）。
* 自动对请求数据进行**脱敏处理**，保护隐私。
* AI 基于上下文深度分析越权风险，并给出置信度评分（例如：`存在越权 (95%)`）。


* 🎨 **智能染色与去重 (Smart Coloring & Dedup)**
* **红绿染色**：自动对比响应长度，差异极小时标记为红色（高危），差异巨大时标记为绿色（安全）。
* **URL 去重**：避免重复扫描同一接口，提升效率。


* 🛡️ **三方对比检测 (3-Way Comparison)**
* 同时维护 **原始请求**、**低权限请求**、**未授权请求** 三份数据快照。
* 支持自定义请求头替换（Cookie/Token）和参数替换。


* ⚙️ **灵活配置 (Flexible Config)**
* 支持域名白名单、方法过滤、路径过滤。
* 支持一键清空和状态重置。



---

## 🛠️ 安装指南 (Installation)

### 前置要求

1. **Burp Suite Professional** 或 **Community** 版本。
2. **Jython Standalone JAR** (下载地址: [Jython官网](https://www.jython.org/download))。

### 安装步骤

1. 打开 Burp Suite，点击 **Extensions** -> **Extensions Settings**。
2. 在 **Python Environment** 中，选择下载好的 `jython-standalone-xxx.jar` 文件路径。
3. 点击 **Extensions** -> **Installed** -> **Add**。
4. Extension type 选择 **Python**。
5. 选择本插件文件 `ai_yue_pro.py`。
6. 点击 **Next**，看到 "AiYue_Pro Loaded!" 即表示安装成功。

---

## 📖 使用手册 (Usage Guide)

### 1. 基础配置 (Basic Configuration)

插件加载后，请切换到 **AiYue_Pro** 标签页。

* **域名白名单 (必填!)**：
* 在右侧配置栏输入测试目标的域名（例如 `example.com`）。
* *注意：为了防止误伤，未配置白名单时插件不会运行。*


* **越权配置 (Low Privilege)**：
* 在浏览器登录一个**低权限账号**（攻击者账号）。
* 抓包复制其 `Cookie` 或 `Authorization` 头，粘贴到 **"越权"** 配置框中。
* *插件会自动将原始请求中的认证头替换为你填写的这些头。*


* **未授权配置 (Unauthorized)**：
* 填写需要移除的头（如 `Cookie`, `Token`），用于模拟未登录访问。



### 2. 启用 AI 分析 (Optional)

如果你希望使用 AI 进行深度研判：

1. 勾选右下角的 **[x] 启用 AI 智能分析**。
2. 填写 **API URL** (支持任何 OpenAI 格式接口):
* *OpenAI*: `https://api.openai.com/v1/chat/completions`
* *通义千问*: `https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions`
* *DeepSeek*: `https://api.deepseek.com/chat/completions`


3. 填写 **API Key** 和 **Model** (如 `gpt-3.5-turbo`, `qwen-plus`)。

### 3. 开始检测

1. 在 Burp Suite 的 Proxy 或 Repeater 中正常浏览网页。
2. AiYue_Pro 会自动在后台抓取符合白名单的 **200 OK** 请求。
3. 观察左侧表格：
* **红色数字**：表示低权限/未授权响应长度与原始响应非常接近（可能存在漏洞）。
* **红色 AI 结果**：表示 AI 认为存在越权风险。


4. 点击表格行，在底部 **AI分析结果** 标签页查看详细报告。

---

## 📸 界面预览 (Screenshots)

![](images/win.png)


---

## ⚠️ 免责声明 (Disclaimer)

本工具仅供**授权的安全测试**和**教育目的**使用。请勿用于非法的网络攻击行为。开发者不对因使用本工具造成的任何直接或间接损失承担责任。

---

## 📝 更新日志 (Changelog)

**v1.0 (Current)**

* 重构核心逻辑，实现无限并发处理。
* 集成 AI 大模型分析功能。
* 优化 UI 布局，支持中文显示与智能染色。
* 增加数据脱敏机制，保护隐私。

---

**Made with ❤️ for Security Researchers.**
