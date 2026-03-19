# -*- coding: utf-8 -*-
# ai_yue_pro.py
# New Name: AiYue_Pro
# Features: IDOR Detection + Parameter Replacement + AI Analysis + Static Resource Filter + Unlimited Concurrency
# Environment: Jython 2.7 + Burp Suite

from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IExtensionStateListener, \
    IBurpExtenderCallbacks, IParameter
from java.awt import BorderLayout, Dimension, GridBagLayout, GridBagConstraints, Insets, Color, Font
from javax.swing import (JSplitPane, JTabbedPane, JPanel, JLabel, JTable,
                         JScrollPane, JTextArea, JCheckBox, JButton, JTextField,
                         BorderFactory, ListSelectionModel, SwingUtilities,
                         SwingConstants, ToolTipManager)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from javax.swing.event import ListSelectionListener
from java.util import ArrayList, HashSet
from java.io import PrintWriter, BufferedReader, InputStreamReader, OutputStreamWriter
from java.net import HttpURLConnection, URL
from java.lang import Thread, Runnable
from java.util.concurrent import Executors
import traceback
import json
import re

# --- 界面文本常量 ---
L_PLUGIN_NAME = u"\u63d2\u4ef6\u540d: AiYue_Pro (AI\u667a\u80fd\u8d8a\u6743\u68c0\u6d4b)"
L_ENABLE = u"\u542f\u52a8\u63d2\u4ef6"
L_CLEAR = u"\u6e05\u7a7a\u5217\u8868"

L_WHITELIST = u"\u57df\u540d\u767d\u540d\u5355 (\u5fc5\u586b)"
L_WHITELIST_TIP = u"\u4f8b\u5982:\nexample.com\napi.test.com"

L_FILTER_METHOD = u"\u8fc7\u6ee4HTTP\u65b9\u6cd5"
L_FILTER_EXT = u"\u8fc7\u6ee4\u9759\u6001\u540e\u7f00 (\u5982 js,png)"
L_FILTER_PATH = u"\u8fc7\u6ee4\u63a5\u53e3\u8def\u5f84"
L_AUTH_CONFIG = u"\u8d8a\u6743: \u586b\u5199\u4f4e\u6743\u9650\u8ba4\u8bc1\u4fe1\u606f\uff08Cookie/Token\uff09"
L_PARAM_CONFIG = u"\u53c2\u6570\u66ff\u6362: \u586b\u5199\u9700\u8981\u66ff\u6362\u7684\u53c2\u6570 (\u6c34\u5e73\u8d8a\u6743)"
L_UNAUTH_CONFIG = u"\u672a\u6388\u6743: \u5c06\u79fb\u9664\u4e0b\u5217\u8ba4\u8bc1\u4fe1\u606f"
L_DEDUPLICATE = u"\u542f\u7528URL\u53bb\u91cd"

L_AI_CONFIG = u"AI\u8bbe\u7f6e (OpenAI\u517c\u5bb9\u63a5\u53e3)"
L_AI_ENABLE = u"\u542f\u7528 AI \u667a\u80fd\u5206\u6790 (\u9700\u914d\u7f6eAPI Key)"
L_API_URL = u"API URL"
L_API_KEY = u"API Key"
L_MODEL = u"Model"

L_TAB_ORIGIN = u"\u539f\u59cb\u6570\u636e\u5305"
L_TAB_LOW = u"\u4f4e\u6743\u9650\u6570\u636e\u5305"
L_TAB_UNAUTH = u"\u672a\u6388\u6743\u6570\u636e\u5305"
L_TAB_AI_RESULT = u"AI\u5206\u6790\u7ed3\u679c"

COL_ID_NAME = u"#"
COL_METHOD_NAME = u"\u7c7b\u578b"
COL_URL_NAME = u"URL"
COL_ORIG_LEN_NAME = u"\u539f\u59cb\u5305\u957f"
COL_LOW_LEN_NAME = u"\u4f4e\u6743\u5305\u957f"
COL_UNAUTH_LEN_NAME = u"\u672a\u6388\u6743\u5305\u957f"
COL_AI_NAME = u"AI\u5206\u6790"

COL_ID = 0
COL_METHOD = 1
COL_URL = 2
COL_LEN_ORIG = 3
COL_LEN_LOW = 4
COL_LEN_UNAUTH = 5
COL_AI = 6

# --- AI System Prompt ---
AI_SYSTEM_PROMPT = u"""# Role
你是一名资深的 Web 安全渗透测试专家，专门负责自动化 API 越权漏洞（Broken Access Control）的审计工作。

# Task
我将提供两个 HTTP 响应数据给你：
1. **[Baseline_Response]**: 原始高权限账号请求成功的响应（作为参照组）。
2. **[Test_Response]**: 将认证信息（Cookie/Token）或请求参数替换为低权限账号后，发送相同请求得到的响应（作为测试组）。

你的任务是分析 [Test_Response] 是否成功获取了本不该获取的高权限数据，从而判断是否存在越权漏洞。

# Analysis Logic (Step-by-Step)
请严格按照以下步骤进行判断：

1. **状态码预筛**:
   - 如果 [Test_Response] 的状态码是 401, 403, 404, 500，通常视为**无漏洞**。
   - 如果状态码与 [Baseline_Response] 不一致，且为 302/301 跳转到登录页，视为**无漏洞**。

2. **关键词过滤**:
   - 检查 [Test_Response] 的 Body 中是否包含拒绝访问的关键词（如 "无权限", "unauthorized", "permission denied", "errcode": 403）。
   - 如果包含上述明确的拒绝语义，视为**无漏洞**。

3. **响应相似度与结构对比**:
   - **响应大小**: 如果 [Test_Response] 的 Body 长度远小于 [Baseline_Response]（例如相差 80% 以上），通常是报错信息，倾向于**无漏洞**。
   - **JSON 结构**: 如果 [Test_Response] 丢失了核心数据字段（如 data, user_info），仅保留了 code 或 message，视为**无漏洞**。

4. **敏感数据验证**:
   - 如果 [Test_Response] 的结构与 [Baseline_Response] 高度相似，且包含了具体的业务数据，则极可能存在**越权漏洞**。

# Output Format
请仅返回 JSON 格式结果，不要包含 Markdown 标记：
{
    "is_vulnerable": true/false,
    "confidence": 0-100,
    "reason": "简短的判断理由"
}
"""


class AiYueUI:
    def __init__(self, callbacks, controller):
        self._callbacks = callbacks
        self._controller = controller

        self.chk_enable = None
        self.chk_dedup = None
        self.chk_ai_enable = None

        self.txt_whitelist = None
        self.txt_filter_method = None
        self.txt_filter_ext = None
        self.txt_filter_path = None
        self.txt_auth_headers = None
        self.txt_param_replace = None
        self.txt_unauth_headers = None

        self.txt_api_url = None
        self.txt_api_key = None
        self.txt_model = None

        self.editor_origin_req = None
        self.editor_origin_res = None
        self.editor_low_req = None
        self.editor_low_res = None
        self.editor_unauth_req = None
        self.editor_unauth_res = None
        self.txt_ai_result = None

        self.main_panel = None
        self.table_model = None
        self.table = None

        self._init_ui()

    def _init_ui(self):
        # Table
        self.table_model = CustomTableModel(self._controller._log)
        self.table = JTable(self.table_model)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(TableSelectionHandler(self._controller))

        center_renderer = DefaultTableCellRenderer()
        center_renderer.setHorizontalAlignment(SwingConstants.CENTER)
        color_renderer = AnalysisColorRenderer(self._controller._log)

        for i in range(self.table.getColumnCount()):
            if i == COL_LEN_LOW or i == COL_LEN_UNAUTH or i == COL_AI:
                self.table.getColumnModel().getColumn(i).setCellRenderer(color_renderer)
            else:
                self.table.getColumnModel().getColumn(i).setCellRenderer(center_renderer)

        self.table.getColumnModel().getColumn(COL_ID).setMaxWidth(40)
        self.table.getColumnModel().getColumn(COL_METHOD).setMaxWidth(60)
        table_scroll = JScrollPane(self.table)

        # Config Panel
        config_panel = JPanel(GridBagLayout())
        config_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 1.0
        c.insets = Insets(3, 2, 3, 2)
        c.gridx = 0

        c.gridy = 0
        config_panel.add(JLabel(L_PLUGIN_NAME), c)

        c.gridy = 1
        panel_btns = JPanel(BorderLayout())
        self.chk_enable = JCheckBox(L_ENABLE)
        self.chk_enable.setSelected(True)
        self.chk_dedup = JCheckBox(L_DEDUPLICATE)
        self.chk_dedup.setSelected(True)
        btn_clear = JButton(L_CLEAR)
        btn_clear.addActionListener(self._controller.action_clear)
        left_btns = JPanel()
        left_btns.add(self.chk_enable)
        left_btns.add(self.chk_dedup)
        panel_btns.add(left_btns, BorderLayout.WEST)
        panel_btns.add(btn_clear, BorderLayout.EAST)
        config_panel.add(panel_btns, c)

        c.gridy = 2
        config_panel.add(JLabel(L_WHITELIST), c)
        c.gridy = 3
        self.txt_whitelist = JTextArea(2, 20)
        self.txt_whitelist.setText("")
        self.txt_whitelist.setBorder(BorderFactory.createEtchedBorder())
        self.txt_whitelist.setToolTipText(L_WHITELIST_TIP)
        ToolTipManager.sharedInstance().registerComponent(self.txt_whitelist)
        config_panel.add(JScrollPane(self.txt_whitelist), c)

        c.gridy = 4
        config_panel.add(JLabel(L_FILTER_METHOD), c)
        c.gridy = 5
        self.txt_filter_method = JTextField("OPTIONS,HEAD")
        config_panel.add(self.txt_filter_method, c)

        c.gridy = 6
        config_panel.add(JLabel(L_FILTER_EXT), c)
        c.gridy = 7
        self.txt_filter_ext = JTextField("css,js,jpg,jpeg,png,gif,woff,woff2,svg,ico")
        config_panel.add(self.txt_filter_ext, c)

        c.gridy = 8
        config_panel.add(JLabel(L_FILTER_PATH), c)
        c.gridy = 9
        self.txt_filter_path = JTextField("")
        config_panel.add(self.txt_filter_path, c)

        c.gridy = 10
        config_panel.add(JLabel(L_AUTH_CONFIG), c)
        c.gridy = 11
        self.txt_auth_headers = JTextArea(3, 20)
        self.txt_auth_headers.setText("Cookie: session=low_priv_user\nAuthorization: Bearer low_priv_token")
        self.txt_auth_headers.setBorder(BorderFactory.createEtchedBorder())
        config_panel.add(JScrollPane(self.txt_auth_headers), c)

        c.gridy = 12
        config_panel.add(JLabel(L_PARAM_CONFIG), c)
        c.gridy = 13
        self.txt_param_replace = JTextArea(2, 20)
        self.txt_param_replace.setText("id=2\nuid=1002")
        self.txt_param_replace.setBorder(BorderFactory.createEtchedBorder())
        config_panel.add(JScrollPane(self.txt_param_replace), c)

        c.gridy = 14
        config_panel.add(JLabel(L_UNAUTH_CONFIG), c)
        c.gridy = 15
        self.txt_unauth_headers = JTextArea(2, 20)
        self.txt_unauth_headers.setText("Cookie\nAuthorization\nToken")
        self.txt_unauth_headers.setBorder(BorderFactory.createEtchedBorder())
        config_panel.add(JScrollPane(self.txt_unauth_headers), c)

        # AI Config
        c.gridy = 16
        ai_panel = JPanel(GridBagLayout())
        ai_panel.setBorder(BorderFactory.createTitledBorder(L_AI_CONFIG))
        ac = GridBagConstraints()
        ac.fill = GridBagConstraints.HORIZONTAL
        ac.weightx = 1.0
        ac.gridx = 0
        ac.insets = Insets(2, 2, 2, 2)

        ac.gridy = 0
        self.chk_ai_enable = JCheckBox(L_AI_ENABLE)
        self.chk_ai_enable.setSelected(False)
        ai_panel.add(self.chk_ai_enable, ac)

        ac.gridy = 1
        ai_panel.add(JLabel(L_API_URL), ac)
        ac.gridy = 2
        self.txt_api_url = JTextField("https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions")
        ai_panel.add(self.txt_api_url, ac)

        ac.gridy = 3
        ai_panel.add(JLabel(L_API_KEY), ac)
        ac.gridy = 4
        self.txt_api_key = JTextField("")
        ai_panel.add(self.txt_api_key, ac)

        ac.gridy = 5
        ai_panel.add(JLabel(L_MODEL), ac)
        ac.gridy = 6
        self.txt_model = JTextField("qwen-plus")
        ai_panel.add(self.txt_model, ac)

        c.gridy = 17
        config_panel.add(ai_panel, c)

        config_scroll = JScrollPane(config_panel)
        config_scroll.setPreferredSize(Dimension(380, 0))

        # Viewers
        self.editor_origin_req = self._callbacks.createMessageEditor(self._controller, False)
        self.editor_origin_res = self._callbacks.createMessageEditor(self._controller, False)
        self.editor_low_req = self._callbacks.createMessageEditor(self._controller, False)
        self.editor_low_res = self._callbacks.createMessageEditor(self._controller, False)
        self.editor_unauth_req = self._callbacks.createMessageEditor(self._controller, False)
        self.editor_unauth_res = self._callbacks.createMessageEditor(self._controller, False)

        self.txt_ai_result = JTextArea()
        self.txt_ai_result.setEditable(False)
        self.txt_ai_result.setLineWrap(True)
        self.txt_ai_result.setFont(Font("Monospaced", Font.PLAIN, 12))
        ai_scroll = JScrollPane(self.txt_ai_result)

        def create_req_res_split(req, res):
            split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
            split.setLeftComponent(req.getComponent())
            split.setRightComponent(res.getComponent())
            split.setDividerLocation(0.5)
            split.setResizeWeight(0.5)
            return split

        bottom_tabs = JTabbedPane()
        bottom_tabs.addTab(L_TAB_ORIGIN, create_req_res_split(self.editor_origin_req, self.editor_origin_res))
        bottom_tabs.addTab(L_TAB_LOW, create_req_res_split(self.editor_low_req, self.editor_low_res))
        bottom_tabs.addTab(L_TAB_UNAUTH, create_req_res_split(self.editor_unauth_req, self.editor_unauth_res))
        bottom_tabs.addTab(L_TAB_AI_RESULT, ai_scroll)

        top_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        top_split.setLeftComponent(table_scroll)
        top_split.setRightComponent(config_scroll)
        top_split.setDividerLocation(0.7)
        top_split.setResizeWeight(0.7)

        self.main_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.main_panel.setTopComponent(top_split)
        self.main_panel.setBottomComponent(bottom_tabs)
        self.main_panel.setDividerLocation(0.5)
        self.main_panel.setResizeWeight(0.5)
        self._callbacks.customizeUiComponent(self.main_panel)

    def get_panel(self):
        return self.main_panel


class LogEntry:
    def __init__(self, id, url, method, origin_rr):
        self._id = id
        self._url = url
        self._method = method
        self._origin_rr = origin_rr
        self._low_rr = None
        self._unauth_rr = None
        self._len_origin = 0
        self._len_low = "..."
        self._len_unauth = "..."
        self._ai_result = ""
        self._ai_detail = ""


class CustomTableModel(AbstractTableModel):
    def __init__(self, log):
        self._log = log
        self._titles = [COL_ID_NAME, COL_METHOD_NAME, COL_URL_NAME, COL_ORIG_LEN_NAME, COL_LOW_LEN_NAME,
                        COL_UNAUTH_LEN_NAME, COL_AI_NAME]

    def getRowCount(self):
        return self._log.size()

    def getColumnCount(self):
        return len(self._titles)

    def getColumnName(self, col):
        return self._titles[col]

    def getValueAt(self, row, col):
        if row >= self._log.size(): return ""
        e = self._log.get(row)
        if col == COL_ID: return str(e._id)
        if col == COL_METHOD: return e._method
        if col == COL_URL: return e._url.toString()
        if col == COL_LEN_ORIG: return str(e._len_origin)
        if col == COL_LEN_LOW: return str(e._len_low)
        if col == COL_LEN_UNAUTH: return str(e._len_unauth)
        if col == COL_AI: return e._ai_result
        return ""


class AnalysisColorRenderer(DefaultTableCellRenderer):
    def __init__(self, log):
        self._log = log
        self.setHorizontalAlignment(SwingConstants.CENTER)

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = super(AnalysisColorRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row,
                                                                             col)
        if isSelected:
            c.setForeground(table.getSelectionForeground());
            c.setBackground(table.getSelectionBackground())
        else:
            c.setForeground(Color.BLACK);
            c.setBackground(Color.WHITE)

        if row < self._log.size():
            entry = self._log.get(row)
            if col == COL_LEN_LOW or col == COL_LEN_UNAUTH:
                if isinstance(entry._len_origin, int):
                    target_len = None
                    if col == COL_LEN_LOW:
                        target_len = entry._len_low
                    elif col == COL_LEN_UNAUTH:
                        target_len = entry._len_unauth
                    if isinstance(target_len, int):
                        diff = abs(entry._len_origin - target_len)
                        threshold = (entry._len_origin * 0.15) + 50
                        if diff < threshold:
                            c.setForeground(Color.RED);
                            c.setFont(c.getFont().deriveFont(Font.BOLD))
                        else:
                            c.setForeground(Color.GREEN.darker());
                            c.setFont(c.getFont().deriveFont(Font.BOLD))
            elif col == COL_AI:
                val_str = str(value)
                if u"True" in val_str or u"true" in val_str:
                    c.setForeground(Color.RED);
                    c.setFont(c.getFont().deriveFont(Font.BOLD))
                    c.setText(val_str.replace("True", u"\u5b58\u5728\u8d8a\u6743").replace("true",
                                                                                           u"\u5b58\u5728\u8d8a\u6743"))
                elif u"False" in val_str or u"false" in val_str:
                    c.setForeground(Color.GREEN.darker());
                    c.setFont(c.getFont().deriveFont(Font.BOLD))
                    c.setText(val_str.replace("False", u"\u5b89\u5168").replace("false", u"\u5b89\u5168"))
        return c


class TableSelectionHandler(ListSelectionListener):
    def __init__(self, controller): self._controller = controller

    def valueChanged(self, e):
        if not e.getValueIsAdjusting(): self._controller.on_row_selected()


class AIService:
    def __init__(self, api_url, api_key, model):
        self.api_url = api_url
        self.api_key = api_key
        self.model = model

    def sanitize(self, text):
        if not text: return ""
        if len(text) > 1000: text = text[:1000] + "...[TRUNCATED]"
        text = re.sub(r'\d{11}', '[PHONE]', text)
        text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[EMAIL]', text)
        return text

    def analyze(self, api_path, status_base, body_base, status_test, body_test):
        try:
            safe_body_base = self.sanitize(body_base)
            safe_body_test = self.sanitize(body_test)

            user_input = {
                "api_path": api_path,
                "baseline_response_status": status_base,
                "baseline_response_body": safe_body_base,
                "test_response_status": status_test,
                "test_response_body": safe_body_test
            }

            data = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": AI_SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(user_input)}
                ],
                "temperature": 0.3
            }
            json_data = json.dumps(data)
            obj = URL(self.api_url)
            con = obj.openConnection()
            con.setRequestMethod("POST")
            con.setRequestProperty("Content-Type", "application/json")
            con.setRequestProperty("Authorization", "Bearer " + self.api_key)
            con.setDoOutput(True)
            writer = OutputStreamWriter(con.getOutputStream(), "UTF-8")
            writer.write(json_data);
            writer.flush();
            writer.close()

            code = con.getResponseCode()
            if code == 200:
                reader = BufferedReader(InputStreamReader(con.getInputStream(), "UTF-8"))
                response = ""
                line = reader.readLine()
                while line: response += line; line = reader.readLine()
                reader.close()
                resp_json = json.loads(response)
                content = resp_json['choices'][0]['message']['content']
                try:
                    clean_content = content.replace("```json", "").replace("```", "").strip()
                    start = clean_content.find('{')
                    end = clean_content.rfind('}') + 1
                    if start != -1 and end != -1:
                        ai_json = json.loads(clean_content[start:end])
                        is_vuln = ai_json.get("is_vulnerable", False)
                        conf = ai_json.get("confidence", 0)
                        reason = ai_json.get("reason", "No reason")
                        summary = "%s (%s%%)" % (str(is_vuln), conf)
                        return summary, reason
                    else:
                        return "Format Error", content
                except:
                    return "Parse Error", content
            else:
                return "API Error", "Code: " + str(code)
        except Exception as e:
            return "Sys Error", str(e)


class AnalysisTask(Runnable):
    def __init__(self, controller, entry):
        self._c = controller;
        self._e = entry

    def run(self):
        try:
            helpers = self._c._helpers
            base_req_info = helpers.analyzeRequest(self._e._origin_rr)
            headers = list(base_req_info.getHeaders())
            body_offset = base_req_info.getBodyOffset()
            body = self._e._origin_rr.getRequest()[body_offset:]
            service = self._e._origin_rr.getHttpService()

            # 1. Low Privilege (认证替换 + 参数替换)
            low_headers = list(headers)
            auth_cfg = self._c._ui.txt_auth_headers.getText().strip()
            if auth_cfg:
                replacements = {}
                for line in auth_cfg.split('\n'):
                    if ':' in line: k, v = line.split(':', 1); replacements[k.strip()] = v.strip()
                low_headers = [h for h in low_headers if h.split(':', 1)[0].strip() not in replacements]
                for k, v in replacements.items(): low_headers.append(k + ": " + v)

            new_req_low = helpers.buildHttpMessage(low_headers, body)

            # ---> 核心修复: 执行参数替换逻辑 (用于水平越权测试) <---
            param_cfg = self._c._ui.txt_param_replace.getText().strip()
            if param_cfg:
                param_replacements = {}
                for line in param_cfg.split('\n'):
                    if '=' in line:
                        k, v = line.split('=', 1)
                        param_replacements[k.strip()] = v.strip()

                if param_replacements:
                    req_info_temp = helpers.analyzeRequest(new_req_low)
                    params = req_info_temp.getParameters()
                    for p in params:
                        p_name = p.getName()
                        if p_name in param_replacements:
                            new_val = param_replacements[p_name]
                            # 使用 Burp 官方 API 安全替换参数，无论它在 URL 还是 Body 还是 Cookie 中
                            new_param = helpers.buildParameter(p_name, new_val, p.getType())
                            new_req_low = helpers.updateParameter(new_req_low, new_param)

            self._e._low_rr = self._c._callbacks.makeHttpRequest(service, new_req_low)
            if self._e._low_rr and self._e._low_rr.getResponse():
                resp = self._e._low_rr.getResponse()
                info = helpers.analyzeResponse(resp)
                self._e._len_low = len(resp) - info.getBodyOffset()
            else:
                self._e._len_low = "Error"

            # 2. Unauth (未授权剔除)
            unauth_headers = list(headers)
            unauth_cfg = self._c._ui.txt_unauth_headers.getText().strip()
            if unauth_cfg:
                to_remove = [x.strip() for x in unauth_cfg.split('\n') if x.strip()]
                final_unauth_headers = []
                for h in unauth_headers:
                    key = h.split(':', 1)[0].strip();
                    should_remove = False
                    for r in to_remove:
                        if key.lower() == r.lower(): should_remove = True; break
                    if not should_remove: final_unauth_headers.append(h)
                unauth_headers = final_unauth_headers
            new_req_unauth = helpers.buildHttpMessage(unauth_headers, body)
            self._e._unauth_rr = self._c._callbacks.makeHttpRequest(service, new_req_unauth)
            if self._e._unauth_rr and self._e._unauth_rr.getResponse():
                resp = self._e._unauth_rr.getResponse()
                info = helpers.analyzeResponse(resp)
                self._e._len_unauth = len(resp) - info.getBodyOffset()
            else:
                self._e._len_unauth = "Error"

            # 3. AI Analysis
            api_key = self._c._ui.txt_api_key.getText().strip()
            is_ai_enabled = self._c._ui.chk_ai_enable.isSelected()
            if is_ai_enabled and api_key and isinstance(self._e._len_low, int):
                self._e._ai_result = "Thinking..."
                SwingUtilities.invokeLater(lambda: self._c._ui.table_model.fireTableDataChanged())

                def get_body_str(rr):
                    if not rr or not rr.getResponse(): return ""
                    resp = rr.getResponse()
                    info = helpers.analyzeResponse(resp)
                    off = info.getBodyOffset()
                    return helpers.bytesToString(resp[off:])

                def get_status(rr):
                    if not rr or not rr.getResponse(): return 0
                    return helpers.analyzeResponse(rr.getResponse()).getStatusCode()

                body_base = get_body_str(self._e._origin_rr)
                status_base = get_status(self._e._origin_rr)
                body_low = get_body_str(self._e._low_rr)
                status_low = get_status(self._e._low_rr)

                ai = AIService(self._c._ui.txt_api_url.getText().strip(), api_key,
                               self._c._ui.txt_model.getText().strip())
                summary, detail = ai.analyze(self._e._url.getPath(), status_base, body_base, status_low, body_low)
                self._e._ai_result = summary
                self._e._ai_detail = detail
            else:
                self._e._ai_result = "Disabled" if not is_ai_enabled else "Skipped"
                self._e._ai_detail = "Skipped"

            SwingUtilities.invokeLater(lambda: self._c._ui.table_model.fireTableDataChanged())
        except:
            traceback.print_exc(file=self._c._stderr)


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("AiYue_Pro")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._log = ArrayList()
        self._selected_entry = None
        self._thread_pool = Executors.newCachedThreadPool()
        self._processed_urls = HashSet()
        self._ui = AiYueUI(callbacks, self)
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerExtensionStateListener(self)
        self._stdout.println("AiYue_Pro v2 (With Static Filter & Param Replace) Loaded!")

    def extensionUnloaded(self):
        self._thread_pool.shutdown()

    def getTabCaption(self):
        return "AiYue_Pro"

    def getUiComponent(self):
        return self._ui.get_panel()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER: return
        if toolFlag not in [IBurpExtenderCallbacks.TOOL_PROXY, IBurpExtenderCallbacks.TOOL_REPEATER]: return
        if not self._ui.chk_enable.isSelected() or messageIsRequest: return

        resp_info = self._helpers.analyzeResponse(messageInfo.getResponse())
        if resp_info.getStatusCode() != 200: return

        req_info = self._helpers.analyzeRequest(messageInfo)
        url = req_info.getUrl()

        whitelist = self._ui.txt_whitelist.getText().strip()
        if not whitelist: return
        hosts = []
        for line in whitelist.replace(',', '\n').split('\n'):
            if line.strip(): hosts.append(line.strip())
        host_match = False
        for h in hosts:
            if h in str(url.getHost()): host_match = True; break
        if not host_match: return

        # Method 过滤
        method_filter = self._ui.txt_filter_method.getText().strip()
        if method_filter:
            skip_methods = [m.strip().upper() for m in method_filter.split(',') if m.strip()]
            if req_info.getMethod().upper() in skip_methods: return

        # ---> 新增: 静态资源后缀过滤 <---
        ext_filter = self._ui.txt_filter_ext.getText().strip()
        if ext_filter:
            skip_exts = [e.strip().lower() for e in ext_filter.split(',') if e.strip()]
            path = url.getPath().lower()
            for ext in skip_exts:
                ext_str = ext if ext.startswith('.') else '.' + ext
                if path.endswith(ext_str): return

        path_filter = self._ui.txt_filter_path.getText().strip()
        if path_filter:
            skip_paths = [p.strip() for p in path_filter.split(',')]
            path = url.getPath()
            for sp in skip_paths:
                if sp in path: return

        if self._ui.chk_dedup.isSelected():
            req_key = req_info.getMethod() + " " + str(url)
            if self._processed_urls.contains(req_key): return
            self._processed_urls.add(req_key)

        orig_len = len(messageInfo.getResponse()) - resp_info.getBodyOffset()
        entry = LogEntry(self._log.size() + 1, url, req_info.getMethod(),
                         self._callbacks.saveBuffersToTempFiles(messageInfo))
        entry._len_origin = orig_len
        self._log.add(entry)
        self._ui.table_model.fireTableRowsInserted(self._log.size() - 1, self._log.size() - 1)
        self._thread_pool.submit(AnalysisTask(self, entry))

    def action_clear(self, e):
        self._log.clear();
        self._processed_urls.clear()
        self._ui.table_model.fireTableDataChanged();
        self.clear_editors()

    def clear_editors(self):
        self._ui.editor_origin_req.setMessage(None, True);
        self._ui.editor_origin_res.setMessage(None, False)
        self._ui.editor_low_req.setMessage(None, True);
        self._ui.editor_low_res.setMessage(None, False)
        self._ui.editor_unauth_req.setMessage(None, True);
        self._ui.editor_unauth_res.setMessage(None, False)
        self._ui.txt_ai_result.setText("")

    def on_row_selected(self):
        row = self._ui.table.getSelectedRow()
        if row == -1: return
        e = self._log.get(row);
        self._selected_entry = e
        self._ui.editor_origin_req.setMessage(e._origin_rr.getRequest() if e._origin_rr else None, True)
        self._ui.editor_origin_res.setMessage(e._origin_rr.getResponse() if e._origin_rr else None, False)
        self._ui.editor_low_req.setMessage(e._low_rr.getRequest() if e._low_rr else None, True)
        self._ui.editor_low_res.setMessage(e._low_rr.getResponse() if e._low_rr else None, False)
        self._ui.editor_unauth_req.setMessage(e._unauth_rr.getRequest() if e._unauth_rr else None, True)
        self._ui.editor_unauth_res.setMessage(e._unauth_rr.getResponse() if e._unauth_rr else None, False)
        self._ui.txt_ai_result.setText(e._ai_detail)

    def getHttpService(self):
        return self._selected_entry._origin_rr.getHttpService() if self._selected_entry else None

    def getRequest(self):
        return self._selected_entry._origin_rr.getRequest() if self._selected_entry else None

    def getResponse(self):
        return self._selected_entry._origin_rr.getResponse() if self._selected_entry else None