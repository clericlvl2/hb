#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { stdin, stdout } from "node:process";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

const PAGE_PATH = fileURLToPath(new URL("./index.html", import.meta.url));
const PAYLOAD_PATTERN = /const PAYLOAD =\s*(['"])[^'"]*\1;/;
const PBKDF2_ITERATIONS = 600000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

/** Normalizes the password the same way the page does before decrypting. */
function normalizePassword(value) {
  return value
    .normalize("NFC")
    .trim()
    .toLowerCase()
    .replace(/ё/g, "е")
    .replace(/\s+/g, " ");
}

/** Derives the AES-GCM key from the password and the salt. */
async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Encrypts the codes into one base64 string: salt, then iv, then ciphertext. */
async function encryptCodes(codes, password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(password, salt);
  const plain = new TextEncoder().encode(JSON.stringify(codes));
  const data = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain),
  );
  const check = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);

  if (new TextDecoder().decode(check) !== JSON.stringify(codes)) {
    throw new Error("Проверка расшифровки не сошлась");
  }

  return Buffer.concat([salt, iv, data]).toString("base64");
}

const prompt = createInterface({ input: stdin, output: stdout });
const games = (await prompt.question("Код Hobby Games: ")).trim();
const tea = (await prompt.question("Номер сертификата чайной: ")).trim();
const password = normalizePassword(await prompt.question("Пароль: "));

prompt.close();

if (!games || !tea || !password) {
  console.error("Все три значения обязательны, страница не изменена.");
  process.exit(1);
}

const page = await readFile(PAGE_PATH, "utf8");

if (!PAYLOAD_PATTERN.test(page)) {
  console.error(
    "В index.html не найдена строка const PAYLOAD, страница не изменена.",
  );
  process.exit(1);
}

const payload = await encryptCodes({ games, tea }, password);

await writeFile(
  PAGE_PATH,
  page.replace(PAYLOAD_PATTERN, `const PAYLOAD = "${payload}";`),
);
console.log("Готово: коды зашифрованы в index.html.");
