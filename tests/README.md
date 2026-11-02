# 离线回归样本

从仓库根目录运行：

```powershell
uv run python -m unittest discover -s tests -v
```

使用标准库 `unittest`，不需要 pytest、外部 API 凭据、模型端点或 SOCKS/HTTP 代理。样本仅包含合成元数据与无害的本地 fixture 描述；检查不得执行 PoC、访问来源 URL 或请求报告目标。

## 目录约定

- `fixtures/admission_cases.json`：按 `fixture_version` 固定的来源、产品候选、材料/引用与审核/搜索预期。
- `test_contract_fixtures.py`：契约 Schema 一致性、来源对象解析、产品消歧、材料引用校验、去重、门槛和状态转换回归。
- `test_search_fixtures.py`：SQLite 内存库检索回归，仅使用合成产品和漏洞记录。
- `schemas/contract-v1.json`：从 `ContractEnvelope.model_json_schema()` 生成；修改领域契约时必须同步 schema 并通过一致性检查。

新增样本时为每个反例记录稳定 `id`、输入事实、预期状态/原因码和可见搜索结果。错误状态须区分可重试的来源/模型故障与内容拒绝；重复转载须保留多个来源断言但只保留一个内容哈希；同名产品、多产品多实现须固定消歧和适用关系预期。测试 fixture 不得包含需要运行的真实攻击载荷。

真实来源试采、模型评估和线上目标验证属于单独的显式在线验收，不能由本离线套件代替。
