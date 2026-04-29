// Глобальные переменные
let masterKey = null;          // ключ AES (CryptoKey)
let globalSalt = null;         // соль, хранящаяся в chrome.storage
let entries = [];              // массив записей из хранилища

// DOM элементы
const masterSection = document.getElementById('master-password-section');
const mainContent = document.getElementById('main-content');
const masterPasswordInput = document.getElementById('master-password');
const unlockBtn = document.getElementById('unlock-btn');
const unlockStatus = document.getElementById('unlock-status');
const generateBtn = document.getElementById('generate-btn');
const copyGeneratedBtn = document.getElementById('copy-generated-btn');
const generatedPasswordField = document.getElementById('generated-password');
const siteInput = document.getElementById('site');
const usernameInput = document.getElementById('username');
const passwordToSaveInput = document.getElementById('password-to-save');
const saveBtn = document.getElementById('save-btn');
const entriesListDiv = document.getElementById('entries-list');

// ---- Вспомогательные функции ----

// Генерация 16-символьного пароля (буквы, цифры, символы)
function generatePassword() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
  const length = 16;
  // Используем криптостойкий генератор (аппаратный RDRAND, если поддерживается)
  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars[array[i] % chars.length];
  }
  return password;
}

// Получение или создание соли в хранилище
async function getOrCreateSalt() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['salt'], (result) => {
      if (result.salt) {
        resolve(new Uint8Array(result.salt));
      } else {
        // Генерация новой соли (16 байт)
        const newSalt = window.crypto.getRandomValues(new Uint8Array(16));
        chrome.storage.local.set({ salt: Array.from(newSalt) }, () => {
          resolve(newSalt);
        });
      }
    });
  });
}

// Вывод ключа из мастер-пароля и соли через PBKDF2
async function deriveKey(masterPassword, salt) {
  const enc = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(masterPassword),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const key = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  return key;
}

// Шифрование пароля (возвращает объект { ciphertext, iv })
async function encryptPassword(password, key) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    enc.encode(password)
  );
  return {
    ciphertext: Array.from(new Uint8Array(ciphertext)),
    iv: Array.from(iv)
  };
}

// Расшифровка пароля
async function decryptPassword(encryptedData, key) {
  const ciphertext = new Uint8Array(encryptedData.ciphertext);
  const iv = new Uint8Array(encryptedData.iv);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decrypted);
}

// Загрузка записей из хранилища
async function loadEntries() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['entries'], (result) => {
      entries = result.entries || [];
      resolve(entries);
    });
  });
}

// Сохранение записей в хранилище
async function saveEntries() {
  return new Promise((resolve) => {
    chrome.storage.local.set({ entries: entries }, resolve);
  });
}

// Отображение списка сохранённых записей (расшифровка паролей)
async function displayEntries() {
  if (!masterKey) return;
  entriesListDiv.innerHTML = '';
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    let decryptedPassword = '';
    try {
      decryptedPassword = await decryptPassword(entry.encryptedPassword, masterKey);
    } catch (e) {
      decryptedPassword = 'Ошибка расшифровки';
    }
    const div = document.createElement('div');
    div.className = 'entry';
    div.innerHTML = `
      <strong>Сайт:</strong> ${escapeHtml(entry.site)}<br>
      <strong>Логин:</strong> ${escapeHtml(entry.username)}<br>
      <strong>Пароль:</strong> <span id="pwd-${i}">${escapeHtml(decryptedPassword)}</span>
      <button data-index="${i}" class="copy-pwd-btn">Копировать пароль</button>
      <button data-index="${i}" class="delete-entry-btn">Удалить</button>
    `;
    entriesListDiv.appendChild(div);
  }
  // Добавляем обработчики на кнопки копирования и удаления
  document.querySelectorAll('.copy-pwd-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const idx = parseInt(btn.dataset.index);
      const entry = entries[idx];
      if (!masterKey) return;
      let pwd;
      try {
        pwd = await decryptPassword(entry.encryptedPassword, masterKey);
        await navigator.clipboard.writeText(pwd);
        alert('Пароль скопирован');
      } catch (err) {
        alert('Не удалось расшифровать пароль');
      }
    });
  });
  document.querySelectorAll('.delete-entry-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const idx = parseInt(btn.dataset.index);
      if (confirm('Удалить запись?')) {
        entries.splice(idx, 1);
        await saveEntries();
        displayEntries(); // обновить список
      }
    });
  });
}

// Простая защита от XSS
function escapeHtml(str) {
  return str.replace(/[&<>]/g, function(m) {
    if (m === '&') return '&amp;';
    if (m === '<') return '&lt;';
    if (m === '>') return '&gt;';
    return m;
  });
}

// ---- Обработчики UI ----

// Разблокировка: ввод мастер-пароля
unlockBtn.addEventListener('click', async () => {
  const masterPwd = masterPasswordInput.value;
  if (!masterPwd) {
    unlockStatus.textContent = 'Введите мастер-пароль';
    return;
  }
  try {
    // Получаем или создаём соль
    globalSalt = await getOrCreateSalt();
    // Выводим ключ
    masterKey = await deriveKey(masterPwd, globalSalt);
    // Загружаем записи
    await loadEntries();
    // Скрываем секцию мастер-пароля, показываем основной интерфейс
    masterSection.style.display = 'none';
    mainContent.style.display = 'block';
    // Отображаем список
    await displayEntries();
  } catch (err) {
    console.error(err);
    unlockStatus.textContent = 'Ошибка разблокировки. Проверьте мастер-пароль.';
  }
});

// Генерация пароля
generateBtn.addEventListener('click', () => {
  const newPwd = generatePassword();
  generatedPasswordField.value = newPwd;
  // Также подставляем в поле "Пароль" для сохранения
  passwordToSaveInput.value = newPwd;
});

// Копирование сгенерированного пароля
copyGeneratedBtn.addEventListener('click', async () => {
  if (generatedPasswordField.value) {
    await navigator.clipboard.writeText(generatedPasswordField.value);
    alert('Сгенерированный пароль скопирован');
  } else {
    alert('Сначала сгенерируйте пароль');
  }
});

// Сохранение записи
saveBtn.addEventListener('click', async () => {
  if (!masterKey) {
    alert('Сначала разблокируйте хранилище мастер-паролем');
    return;
  }
  const site = siteInput.value.trim();
  const username = usernameInput.value.trim();
  const password = passwordToSaveInput.value.trim();
  if (!site || !username || !password) {
    alert('Заполните все поля');
    return;
  }
  try {
    const encrypted = await encryptPassword(password, masterKey);
    const newEntry = {
      site: site,
      username: username,
      encryptedPassword: encrypted
    };
    entries.push(newEntry);
    await saveEntries();
    // Очистить поля
    siteInput.value = '';
    usernameInput.value = '';
    passwordToSaveInput.value = '';
    // Обновить список
    await displayEntries();
    alert('Пароль сохранён');
  } catch (err) {
    console.error(err);
    alert('Ошибка шифрования');
  }
});