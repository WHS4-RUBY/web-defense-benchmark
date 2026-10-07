import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { apiPath, get, send, upload } from "../src/api.ts";

test("API calls follow the selected RUBY Market entry without a Referer", async () => {
  globalThis.window = { location: { pathname: "/" } };
  assert.equal(apiPath("/api/products?q=test"), "/api/products?q=test");

  globalThis.window.location.pathname = "/ruby-shop/";
  assert.equal(apiPath("/api/products?q=test"), "/ruby-shop/api/products?q=test");
  assert.equal(apiPath("/api/products/1/image"), "/ruby-shop/api/products/1/image");
  assert.equal(apiPath("/assets/logo.png"), "/assets/logo.png");

  const requests = [];
  globalThis.fetch = async (path) => {
    requests.push(path);
    return { ok: true, status: 200, json: async () => ({}) };
  };
  await get("/api/products");
  await send("POST", "/api/orders", {});
  await upload("/api/tickets", new FormData());
  assert.deepEqual(requests, [
    "/ruby-shop/api/products",
    "/ruby-shop/api/orders",
    "/ruby-shop/api/tickets",
  ]);
});

test("built assets resolve below root and /ruby-shop/", () => {
  const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");
  const assets = [...html.matchAll(/(?:src|href)="([^"]*assets\/[^"]+)"/g)].map(
    (match) => match[1],
  );
  assert.ok(assets.length >= 2, "expected script and stylesheet assets");
  for (const asset of assets) {
    assert.match(asset, /^\.\/assets\//);
    assert.match(new URL(asset, "http://example.test/").pathname, /^\/assets\//);
    assert.match(
      new URL(asset, "http://example.test/ruby-shop/").pathname,
      /^\/ruby-shop\/assets\//,
    );
  }
});
