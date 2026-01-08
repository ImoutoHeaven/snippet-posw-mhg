# snippets-caas（参考实现）

这是一个“Challenge-as-a-Service（CaaS）”参考实现，设计目标：

- **独立域部署**（如 `caas.example.com`），与业务域、Gate 组件解耦
- **postMessage 优先**（iframe/popup），**redirect 兜底**
- `chal`/`state`/`proofToken` 均为**无状态可验**（HMAC + AEAD）
- Phase 2（PoW）**直接集成在同一份 `caas.js`**，但默认不依赖 `request.cf.*` 做绑定；绑定信号由调用方注入到 `ctx`/`chal` 后由业务后端消费时校验

## 目录结构

- `caas/caas.js`：服务端 Snippet/Worker（`/__pow/v1/*`）
- `caas/template.html`：Turnstile landing 最小 HTML 模板（由构建脚本注入到 `caas.js`）
- `caas/glue.js`：landing 前端（postMessage 握手、Turnstile、可选 PoW）
- `caas/frontend/caas-client.js`：业务前端集成库（iframe/popup + postMessage）
- `caas/sdk/node.js`：后端 SDK（Node 18+）
- `caas/examples/node-demo.mjs`：单个示例（业务后端 `/api/caas/*` + 静态页面）
- `caas/build.mjs`：构建脚本（输出 `dist/caas_snippet.js`，并检查 32KB）

## 构建

在仓库根目录已安装依赖（`esbuild` / `html-minifier-terser` / `terser`）的前提下：

```bash
node caas/build.mjs
```

产物位于 `dist/caas_snippet.js`（根目录 `dist/` 默认已被忽略）。

## 示例（Node）

```bash
CAAS_ORIGIN="https://caas.example.com" \
CAAS_SERVICE_TOKEN="replace-me" \
node caas/examples/node-demo.mjs
```

打开 `http://localhost:8788/`，会调用本地 `/api/caas/generate` 与 `/api/caas/attest`。
