# Free VPN Clash Aggregator

这个仓库把 11 个公开的 GitHub Clash/V2Ray 节点项目合并为 Clash Meta 配置，失败的上游会被隔离，节点会去重，GitHub Actions 每小时重新抓取并提交生成文件。

## 输出文件

- **`output/clash.yaml`**：全部去重后的聚合节点，不做最大节点数 / 区域数量限制。
- **`output/best.yaml`**：通过本地 mihomo 实例真实测速、能连通 `www.google.com` 与 `www.youtube.com` **全部**目标的节点（两个目标都必须可达才保留）。每个节点带 `hit_count` 累计值（历史 best.yaml 中已存在的节点每次命中 +1，新节点记为 1），节点按 `hit_count` 从高到低排序，并在排序后应用最大节点数 / 区域数量限制。
- **`output/error-proxies.json`**：检测时失败代理的缓存（按指纹记录失败类型，如 DNS 解析错误 / 连接失败 / 超时等）。只缓存确定性的网络失败（`dns`/`connect`/`timeout`），7 天后过期；模糊/疑似误判的失败（`unknown`/`auth`/`http`/`controller`，常是 TLS 握手或分类错误）**不缓存**，每次运行会重新测试，避免把其实可连通的节点永久跳过。测试时会跳过缓存中的硬失败节点，加快速度。
- **`output/source-status.json`**：每个上游最近一次抓取是否成功，以及本次测试通过数、跳过数、各失败类型计数、best.yaml 节点数等统计。

## Clash Verge 导入

仓库发布后，将下面的 `OWNER/REPO` 替换成你的 GitHub 仓库路径，然后在 Clash Verge Rev 的订阅管理中粘贴：

```text
https://raw.githubusercontent.com/OWNER/REPO/main/output/clash.yaml
```

如果仓库是公开的，这个链接会随 Actions 更新自动返回最新版配置。想只保留稳定可用的节点，可订阅 `output/best.yaml`。

## 本地运行

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
.venv/Scripts/python scripts/update.py
```

- `MAX_NODES=1000` 与 `REGION_CAP=100` 作用于 `output/best.yaml`（按 `hit_count` 排序后应用），不限制 `output/clash.yaml`。
- 连通性测试分两阶段：先用高并发 TCP 预筛（`PRESCREEN_WORKERS`，默认 50）快速丢弃约 80% 的死节点，再对存活节点经本地 mihomo 实例做完整代理测试，测试 `www.google.com` 与 `www.youtube.com` 两个目标网站。完整测试由多个并行 mihomo 实例（`WORKERS`，默认 8）分担，每个实例使用独立端口，避免串行单端口导致的竞争与超时。每个目标的 `--connect-timeout` 由 `TEST_CONNECT_TIMEOUT`（默认 3 秒）、总时限由 `TEST_TIMEOUT`（默认 5 秒）控制。可用 `TEST_TARGETS`、`TEST_CONNECT_TIMEOUT`、`TEST_TIMEOUT`、`WORKERS`、`PRESCREEN_WORKERS`、`PRESCREEN_TIMEOUT` 调整测试参数。
- 节点越多，Clash Verge 启动和测速越慢，如需调整请自行权衡。

## 安全与合规

这些节点来自未知的第三方公开服务，不能视为可信 VPN。不要通过它们登录银行、邮箱、代码仓库或传输敏感数据；请遵守所在地区法律和各上游项目许可证。上游项目可能随时删除节点或改变格式，工作流会在全部源失败时退出而保留上一版可用文件。

## 上游项目

见 [`sources.yaml`](sources.yaml)。来源包括 PuddinCat/BestClash、Au1rxx/free-vpn-subscriptions、awesome-vpn/awesome-vpn、vxiaov/free_proxies、ermaozi/get_subscribe、anaer/Sub、ermaozi01/free_clash_vpn、peasoft/NoMoreWalls、NiceVPN123/NiceVPN、chengaopan/AutoMergePublicNodes、cbusifabcap/daily_free_vpn。
