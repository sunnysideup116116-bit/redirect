/**
 * 專案轉跳與驗證控制核心邏輯
 *
 * 流程：
 * - 時間已到（11/26 08:30 後）→ 直接顯示選擇畫面（App / 網頁版）
 * - 時間未到 → 顯示倒數與密碼畫面 → 密碼正確後進入選擇畫面
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
  // 2. 目標 URL 動態解密（兩組加密連結，封裝於閉包內）
  // ============================================================
  const _SALT = [
    77, 105, 115, 68, 97, 116, 105, 110, 103, 65, 112, 112, 82, 101, 108, 101,
    97, 115, 101, 50, 48, 50, 54,
  ];

  function _decrypt(payload) {
    const bin = atob(payload);
    let out = "";
    for (let i = 0; i < bin.length; i++) {
      out += String.fromCharCode(
        bin.charCodeAt(i) ^ _SALT[i % _SALT.length] ^ ((i * 7 + 13) % 256),
      );
    }
    return out;
  }

  // Google Play 商店連結（加密）
  function _getAppUrl() {
    return _decrypt(
      "KAkcFjt+cX9SYUJTHWpsfHubi47K/fzMr7vo2cCe0PHc96Q0CQgTFjo6PmMXQ2FQQw5nb2OekqCPiZK787m/wcGIjJGvzQ==",
    );
  }

  // 網頁版連結（加密）
  function _getWebUrl() {
    return _decrypt(
      "KAkcFjt+cX9ReE1ESn5qd3mCnpGYpKDS6uLlwtGf1ujY7P4yQhUdUDIodWMdGS9eXlAndnGJhbw=",
    );
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
    const choiceState = document.getElementById("choiceState");
    const redirectState = document.getElementById("redirectState");
    const redirectDesc = document.getElementById("redirectDesc");
    const passwordForm = document.getElementById("passwordForm");
    const passwordInput = document.getElementById("passwordInput");
    const errorMessage = document.getElementById("errorMessage");
    const submitBtn = document.getElementById("submitBtn");
    const btnApp = document.getElementById("btnApp");
    const btnWeb = document.getElementById("btnWeb");
    const lockImage = document.getElementById("lockImage");
    const blockImage = document.getElementById("blockImage");
    const countdownCard = document.getElementById("countdownCard");
    const lockHeaderGroup = document.getElementById("lockHeaderGroup");
    const blockedMsg = document.getElementById("blockedMsg");

    // 錯誤次數計數（靜默計數，不提示剩餘次數）
    let wrongCount = 0;
    const MAX_WRONG = 3;

    // 倒數計時元素
    const cdDays = document.getElementById("cdDays");
    const cdHours = document.getElementById("cdHours");
    const cdMinutes = document.getElementById("cdMinutes");
    const cdSeconds = document.getElementById("cdSeconds");

    const unlockTimestamp = new Date(UNLOCK_TIME_ISO).getTime();
    let countdownTimerId = null;

    // 顯示選擇畫面
    function showChoiceState() {
      if (countdownTimerId) {
        clearInterval(countdownTimerId);
        countdownTimerId = null;
      }
      lockState.classList.add("hidden");
      redirectState.classList.add("hidden");
      choiceState.classList.remove("hidden");
    }

    // 執行轉跳到指定目標
    function navigateTo(urlGetter, description) {
      choiceState.classList.add("hidden");
      lockState.classList.add("hidden");
      redirectState.classList.remove("hidden");
      redirectDesc.textContent = description;

      setTimeout(() => {
        const target = urlGetter();
        window.location.replace(target);
      }, 400);
    }

    // 綁定選擇按鈕事件
    btnApp.addEventListener("click", () => {
      navigateTo(_getAppUrl, "即將為您導向 Google Play 商店...");
    });

    btnWeb.addEventListener("click", () => {
      navigateTo(_getWebUrl, "即將為您導向網頁版...");
    });

    // 更新倒數畫面
    function updateCountdown() {
      const now = getEstimatedTime();
      const remaining = unlockTimestamp - now;

      if (remaining <= 0) {
        showChoiceState();
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

    // 檢查是否已達開放時間
    if (getEstimatedTime() >= unlockTimestamp) {
      showChoiceState();
    } else {
      // 啟動倒數
      updateCountdown();
      countdownTimerId = setInterval(updateCountdown, 1000);

      // 非同步伺服器時間校正
      await syncServerTime();
      updateCountdown();
    }

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

    // 觸發封鎖畫面（連錯 3 次）——DOM 雙圖切換，零載入延遲
    function triggerBlock() {
      if (countdownTimerId) {
        clearInterval(countdownTimerId);
        countdownTimerId = null;
      }
      // 瞬間隱藏 Warning 圖，顯示預先載入的 Block 圖
      if (lockImage) lockImage.classList.add("hidden");
      if (blockImage) blockImage.classList.remove("hidden");
      countdownCard.style.display = "none";
      lockHeaderGroup.style.display = "none";
      passwordForm.style.display = "none";
      blockedMsg.classList.remove("hidden");
    }

    // 表單驗證提交 → 密碼正確則進入選擇畫面
    passwordForm.addEventListener("submit", (e) => {
      e.preventDefault();
      clearError();

      const userInput = passwordInput.value.trim();
      if (!userInput) {
        showError("請輸入通關密碼！");
        return;
      }

      const hashedInput = computeSha256(userInput);

      if (hashedInput === AUTH_PASSWORD_HASH) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span>驗證成功...</span>`;
        setTimeout(() => {
          showChoiceState();
        }, 300);
      } else {
        wrongCount++;
        if (wrongCount >= MAX_WRONG) {
          triggerBlock();
        } else {
          showError("密碼錯誤！請重新確認");
        }
      }
    });

    // 輸入時自動清除錯誤訊息
    passwordInput.addEventListener("input", () => {
      if (errorMessage.classList.contains("visible")) {
        clearError();
      }
    });

    // 禁用右鍵選單
    document.addEventListener("contextmenu", (e) => {
      e.preventDefault();
    });

    // 禁用圖片與元素拖移
    document.addEventListener("dragstart", (e) => {
      e.preventDefault();
    });

    // 自動對焦（僅在鎖定畫面可見時）
    if (!lockState.classList.contains("hidden")) {
      setTimeout(() => {
        passwordInput.focus();
      }, 100);
    }
  });
})();
