/**
 * 專案轉跳與驗證控制核心邏輯
 *
 * 包含：
 * 1. 台灣時間 (UTC+8) 自動判定與倒數計時（目標開放時間：11/26 08:30）
 * 2. 伺服器時間校驗（防範使用者手動竄改本機系統時鐘）
 * 3. 閉包封裝（IIFE，防止透過 F12 Console 全域變數直接呼叫）
 * 4. 密碼雜湊防篡改比對 (非明文保存)
 * 5. 目標 URL 混淆加密防 F12 搜尋
 */

(() => {
  "use strict";

  // ============================================================
  // 1. 參數與時間設定 (台灣時間 11/26 08:30 開放)
  // ============================================================
  const UNLOCK_TIME_ISO = "2026-11-26T08:30:00+08:00";
  const AUTH_PASSWORD_HASH =
    "1bec026ad7b921c876e44e89dd076cd90aab9665e0cd0b38512d137982acbd3b";

  // ============================================================
  // 2. 目標 URL 動態解密 (封裝於閉包內，F12 Console 無法直接讀取)
  // ============================================================
  function _getDestinationUrl() {
    const _payload =
      "KAkcFjt+cX9SYUJTHWpsfHubi47K/fzMr7vo2cCe0PHc96Q0CQgTFjo6PmMXQ2FQQw5nb2OekqCPiZK787m/wcGIjJGvzQ==";
    const _salt = [
      77, 105, 115, 68, 97, 116, 105, 110, 103, 65, 112, 112, 82, 101, 108, 101,
      97, 115, 101, 50, 48, 50, 54,
    ];
    const _bin = atob(_payload);
    let _result = "";
    for (let i = 0; i < _bin.length; i++) {
      _result += String.fromCharCode(
        _bin.charCodeAt(i) ^ _salt[i % _salt.length] ^ ((i * 7 + 13) % 256),
      );
    }
    return _result;
  }

  // ============================================================
  // 3. 純原生 SHA-256 演算法
  // ============================================================
  function computeSha256(ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    let i, j;
    let result = "";
    let words = [];
    const asciiBitLength = ascii.length * 8;
    const hash = (computeSha256.h = computeSha256.h || []);
    const k = (computeSha256.k = computeSha256.k || []);
    let primeCounter = k.length;
    const isComposite = {};

    for (let candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (i = 0; i < 313; i += candidate) {
          isComposite[i] = candidate;
        }
        hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }

    const h = hash.slice(0);
    words = [];
    for (i = 0; i < ascii.length; i++) {
      const code = ascii.charCodeAt(i);
      words[i >> 2] |= code << ((3 - (i % 4)) * 8);
    }
    words[asciiBitLength >> 5] |= 0x80 << ((3 - (asciiBitLength % 32) / 8) * 8);
    words[(((asciiBitLength + 64) >> 9) << 4) + 15] = asciiBitLength;

    for (i = 0; i < words.length; i += 16) {
      const w = words.slice(i, i + 16);
      const oldHash = h.slice(0);
      for (j = 0; j < 64; j++) {
        const w15 = w[j - 15],
          w2 = w[j - 2];
        const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
        const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
        w[j] = j < 16 ? w[j] | 0 : (w[j - 16] + s0 + w[j - 7] + s1) | 0;
        const ch = (h[4] & h[5]) ^ (~h[4] & h[6]);
        const maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
        const temp1 =
          (h[7] +
            (rightRotate(h[4], 6) ^
              rightRotate(h[4], 11) ^
              rightRotate(h[4], 25)) +
            ch +
            k[j] +
            w[j]) |
          0;
        const temp2 =
          ((rightRotate(h[0], 2) ^
            rightRotate(h[0], 13) ^
            rightRotate(h[0], 22)) +
            maj) |
          0;
        h[7] = h[6];
        h[6] = h[5];
        h[5] = h[4];
        h[4] = (h[3] + temp1) | 0;
        h[3] = h[2];
        h[2] = h[1];
        h[1] = h[0];
        h[0] = (temp1 + temp2) | 0;
      }
      for (j = 0; j < 8; j++) {
        h[j] = (h[j] + oldHash[j]) | 0;
      }
    }

    for (i = 0; i < 8; i++) {
      for (j = 3; j >= 0; j--) {
        const b = (h[i] >> (8 * j)) & 255;
        result += (b < 16 ? "0" : "") + b.toString(16);
      }
    }
    return result;
  }

  // ============================================================
  // 4. 時間取得（支援伺服器校時，防止使用者偷改本機系統時間）
  // ============================================================
  let serverTimeDelta = 0;

  function getEstimatedTime() {
    return Date.now() + serverTimeDelta;
  }

  async function syncServerTime() {
    try {
      // 透過向伺服器發送輕量 HEAD 請求取得真實 HTTP Date 標頭
      const resp = await fetch(window.location.href, {
        method: "HEAD",
        cache: "no-store",
      });
      const dateHeader = resp.headers.get("date");
      if (dateHeader) {
        const actualServerTime = new Date(dateHeader).getTime();
        serverTimeDelta = actualServerTime - Date.now();
      }
    } catch (err) {
      // 本地 file:// 或離線時使用裝置本機時間
    }
  }

  // ============================================================
  // 5. 畫面渲染與事件控制
  // ============================================================
  document.addEventListener("DOMContentLoaded", async () => {
    const lockState = document.getElementById("lockState");
    const redirectState = document.getElementById("redirectState");
    const passwordForm = document.getElementById("passwordForm");
    const passwordInput = document.getElementById("passwordInput");
    const errorMessage = document.getElementById("errorMessage");
    const submitBtn = document.getElementById("submitBtn");

    // 倒數計時元素
    const cdDays = document.getElementById("cdDays");
    const cdHours = document.getElementById("cdHours");
    const cdMinutes = document.getElementById("cdMinutes");
    const cdSeconds = document.getElementById("cdSeconds");

    const unlockTimestamp = new Date(UNLOCK_TIME_ISO).getTime();
    let countdownTimerId = null;

    // 執行轉跳
    function executeRedirect(delayMs = 400) {
      if (countdownTimerId) {
        clearInterval(countdownTimerId);
        countdownTimerId = null;
      }
      lockState.classList.add("hidden");
      redirectState.classList.remove("hidden");

      setTimeout(() => {
        const target = _getDestinationUrl();
        window.location.replace(target);
      }, delayMs);
    }

    // 更新倒數畫面
    function updateCountdown() {
      const now = getEstimatedTime();
      const remaining = unlockTimestamp - now;

      if (remaining <= 0) {
        executeRedirect(0);
        return;
      }

      const days = Math.floor(remaining / (1000 * 60 * 60 * 24));
      const hours = Math.floor((remaining / (1000 * 60 * 60)) % 24);
      const minutes = Math.floor((remaining / (1000 * 60)) % 60);
      const seconds = Math.floor((remaining / 1000) % 60);

      if (cdDays) cdDays.textContent = String(days).padStart(2, "0");
      if (cdHours) cdHours.textContent = String(hours).padStart(2, "0");
      if (cdMinutes) cdMinutes.textContent = String(minutes).padStart(2, "0");
      if (cdSeconds) cdSeconds.textContent = String(seconds).padStart(2, "0");
    }

    // 啟動本機初始倒數
    updateCountdown();
    countdownTimerId = setInterval(updateCountdown, 1000);

    // 非同步進行伺服器時間校正（防止使用者手動修改電腦時間）
    await syncServerTime();
    updateCountdown();

    // 顯示錯誤訊息
    function showError(msg) {
      errorMessage.textContent = msg;
      errorMessage.classList.add("visible");
      passwordInput.focus();
      passwordInput.select();
    }

    // 清除錯誤提示
    function clearError() {
      errorMessage.textContent = "";
      errorMessage.classList.remove("visible");
    }

    // 表單驗證提交
    passwordForm.addEventListener("submit", (e) => {
      e.preventDefault();
      clearError();

      const userInput = passwordInput.value.trim();
      if (!userInput) {
        showError("請輸入通關密碼！");
        return;
      }

      // 計算輸入內容的 SHA-256 雜湊值進行比對
      const hashedInput = computeSha256(userInput);

      if (hashedInput === AUTH_PASSWORD_HASH) {
        // 驗證成功
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span>驗證成功...</span>`;
        executeRedirect(300);
      } else {
        // 驗證失敗
        showError("密碼錯誤！請重新確認");
      }
    });

    // 輸入時自動清除錯誤訊息
    passwordInput.addEventListener("input", () => {
      if (errorMessage.classList.contains("visible")) {
        clearError();
      }
    });

    // 自動對焦
    setTimeout(() => {
      passwordInput.focus();
    }, 100);
  });
})();
