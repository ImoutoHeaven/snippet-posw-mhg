import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";

const setupDom = () => {
  const makeEl = () => ({
    style: { setProperty() {} },
    classList: { add() {}, remove() {} },
    appendChild() {},
    addEventListener() {},
    remove() {},
    innerHTML: "",
    textContent: "",
  });
  const store = new Map();
  const getEl = (id) => {
    if (!store.has(id)) store.set(id, makeEl());
    return store.get(id);
  };
  globalThis.document = {
    title: "",
    head: { appendChild() {} },
    documentElement: { appendChild() {} },
    body: { innerHTML: "", appendChild() {}, style: { setProperty() {} } },
    createElement: () => makeEl(),
    getElementById: (id) => getEl(id),
    querySelectorAll: () => [],
    addEventListener() {},
  };
  globalThis.window = {
    location: { href: "https://example.com/", replace() {}, reload() {} },
    parent: null,
    opener: null,
    innerWidth: 1200,
    innerHeight: 800,
  };
  globalThis.window.parent = globalThis.window;
  Object.defineProperty(globalThis, "navigator", {
    value: { languages: ["en-US"], language: "en-US" },
    configurable: true,
  });
  globalThis.setTimeout = (fn) => 0;
  globalThis.requestAnimationFrame = () => 0;
};

setupDom();
const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const glueUrl = `${pathToFileURL(join(repoRoot, "glue.js")).href}?v=${Date.now()}`;
const glue = await import(glueUrl);

test("resolveLocale selects supported languages", () => {
  assert.equal(glue.resolveLocale(["zh-CN", "en-US"]), "zh");
  assert.equal(glue.resolveLocale(["zh-TW", "en-US"]), "zh_hant");
  assert.equal(glue.resolveLocale(["zh-HK"]), "zh_hant");
  assert.equal(glue.resolveLocale(["zh-MO"]), "zh_hant");
  assert.equal(glue.resolveLocale(["ja-JP", "en-US"]), "ja");
  assert.equal(glue.resolveLocale(["ko-KR", "en-US"]), "ko");
  assert.equal(glue.resolveLocale(["fr-FR"]), "fr");
  assert.equal(glue.resolveLocale(["en-GB"]), "en");
  assert.equal(glue.resolveLocale(["es-ES"]), "en");
});

test("translate returns localized text and formats variables", () => {
  assert.equal(glue.translate("zh", "title_verifying"), "验证中...");
  assert.equal(glue.translate("zh_hant", "title_verifying"), "驗證中...");
  assert.equal(glue.translate("ja", "title_verifying"), "確認中...");
  assert.equal(glue.translate("ko", "title_verifying"), "확인 중...");
  assert.equal(glue.translate("fr", "title_verifying"), "Vérification...");
  assert.equal(
    glue.translate("en", "connection_retry", { ms: 500 }),
    "Connection error. Retrying in 500ms..."
  );
  assert.equal(
    glue.translate("fr", "connection_retry", { ms: 500 }),
    "Erreur de connexion. Nouvelle tentative dans 500ms..."
  );
});

test("translate falls back to key when missing", () => {
  assert.equal(glue.translate("ja", "missing_key"), "missing_key");
});

test("glue i18n does not include recaptcha-only strings", () => {
  assert.equal(glue.translate("en", "loading_recaptcha"), "loading_recaptcha");
  assert.equal(glue.translate("zh", "loading_recaptcha"), "loading_recaptcha");
  assert.equal(glue.translate("zh_hant", "loading_recaptcha"), "loading_recaptcha");
  assert.equal(glue.translate("ja", "loading_recaptcha"), "loading_recaptcha");
  assert.equal(glue.translate("ko", "loading_recaptcha"), "loading_recaptcha");
  assert.equal(glue.translate("fr", "loading_recaptcha"), "loading_recaptcha");
});

test("CJK locales keep commit/challenge/consume as English terms", () => {
  assert.equal(glue.translate("zh", "submitting_commit"), "提交 Commit...");
  assert.equal(glue.translate("zh", "requesting_challenge"), "请求 Challenge...");
  assert.equal(glue.translate("zh", "no_challenge"), "没有 Challenge");
  assert.equal(glue.translate("zh", "consume_missing"), "缺少 Consume");

  assert.equal(glue.translate("zh_hant", "submitting_commit"), "提交 Commit...");
  assert.equal(glue.translate("zh_hant", "requesting_challenge"), "請求 Challenge...");
  assert.equal(glue.translate("zh_hant", "no_challenge"), "沒有 Challenge");
  assert.equal(glue.translate("zh_hant", "consume_missing"), "缺少 Consume");

  assert.equal(glue.translate("ja", "submitting_commit"), "Commit を送信中...");
  assert.equal(glue.translate("ja", "requesting_challenge"), "Challenge を要求中...");
  assert.equal(glue.translate("ja", "no_challenge"), "No Challenge");
  assert.equal(glue.translate("ja", "consume_missing"), "Consume がありません");

  assert.equal(glue.translate("ko", "submitting_commit"), "Commit 제출 중...");
  assert.equal(glue.translate("ko", "requesting_challenge"), "Challenge 요청 중...");
  assert.equal(glue.translate("ko", "no_challenge"), "No Challenge");
  assert.equal(glue.translate("ko", "consume_missing"), "Consume 누락");
});

test("title uses shine class while verifying", () => {
  assert.match(document.body.innerHTML, /id="t"[^>]*class="[^"]*shine/);
});
