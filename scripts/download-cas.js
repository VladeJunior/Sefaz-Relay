#!/usr/bin/env node
/**
 * Baixa as cadeias raiz da ICP-Brasil e gera certs/icp-brasil-bundle.pem
 * Executado automaticamente no `npm install` (postinstall).
 *
 * Fontes oficiais:
 *  - AC Raiz ICP-Brasil v2/v5/v10 (acraiz.icpbrasil.gov.br)
 *  - ACs intermediárias mais usadas para servidores SEFAZ (Serpro, Soluti, Certisign, etc.)
 *
 * Os arquivos .crt são DER; convertemos para PEM e concatenamos.
 */
const https = require("https");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const URLS = [
  // AC Raízes ICP-Brasil
  "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv2.crt",
  "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv5.crt",
  "http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv10.crt",
  // ACs intermediárias frequentemente usadas pelos servidores SEFAZ
  "http://acraiz.icpbrasil.gov.br/credenciadas/SERPRO/v5/AC_SERPRO_v5.crt",
  "http://acraiz.icpbrasil.gov.br/credenciadas/SERPRO/v4/AC_SERPRO_v4.crt",
  "http://acraiz.icpbrasil.gov.br/credenciadas/SOLUTI/v5/AC_SOLUTI_v5.crt",
  "http://acraiz.icpbrasil.gov.br/credenciadas/CERTISIGN/v5/AC_Certisign_RFB_G5.crt",
];

const OUT_DIR = path.join(__dirname, "..", "certs");
const OUT_FILE = path.join(OUT_DIR, "icp-brasil-bundle.pem");

if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

function fetchBuffer(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith("https") ? require("https") : require("http");
    lib
      .get(url, { timeout: 30000 }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
          return resolve(fetchBuffer(res.headers.location, redirects - 1));
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode} em ${url}`));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
      })
      .on("error", reject);
  });
}

function derToPem(derBuffer) {
  const b64 = derBuffer.toString("base64");
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

function isPem(buf) {
  return buf.toString("utf-8", 0, 30).includes("BEGIN CERTIFICATE");
}

(async () => {
  const pemParts = [];
  let ok = 0;
  let fail = 0;

  for (const url of URLS) {
    try {
      const buf = await fetchBuffer(url);
      const pem = isPem(buf) ? buf.toString("utf-8") : derToPem(buf);
      pemParts.push(`# ${url}\n${pem}`);
      ok++;
      console.log(`✓ ${url}`);
    } catch (err) {
      fail++;
      console.warn(`✗ ${url} — ${err.message}`);
    }
  }

  if (pemParts.length === 0) {
    console.error("Nenhuma cadeia baixada. Bundle não gerado.");
    process.exit(0); // não bloqueia o build; o servidor segue com CAs padrão
  }

  fs.writeFileSync(OUT_FILE, pemParts.join("\n"));
  console.log(`\nBundle salvo em ${OUT_FILE} (${ok} OK, ${fail} falhas).`);
})();
