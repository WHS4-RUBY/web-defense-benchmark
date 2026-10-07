"use strict";

// 관리 화면은 브라우저를 실행하는 컴퓨터의 SSH 터널에서만 접근한다.
const adminUrl = new URL("http://127.0.0.1:8088/__detection/dashboard");

const protectedUrl = new URL("/", window.location.href);
protectedUrl.protocol = "http:";
protectedUrl.port = "80";

const adminLink = document.getElementById("admin-link");
adminLink.href = adminUrl.href;
adminLink.textContent = `${adminUrl.href} · 현재 대상 확인·변경 ↗`;

const protectedLink = document.getElementById("protected-link");
protectedLink.href = protectedUrl.href;
protectedLink.textContent = `${protectedUrl.href} · 공격 테스트 경로 열기 ↗`;

for (const [id, port] of [["juice-root-link", "3021"], ["ruby-root-link", "3022"]]) {
  const url = new URL("/", window.location.href);
  url.port = port;
  const link = document.getElementById(id);
  link.href = url.href;
  link.textContent = url.href;
}
