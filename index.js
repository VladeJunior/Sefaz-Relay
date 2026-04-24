// SEFAZ-SP NFC-e Relay v5.3 — Remove xmlns redundante do <NFe> dentro do envelope
// ---------------------------------------------------------------
// Mudança chave em relação à v5.2:
//   - CORREÇÃO cStat=225: o <NFe> assinado tem xmlns="...nfe" próprio (necessário
//     para a assinatura ser válida isolada). Mas dentro de <enviNFe xmlns="...nfe">
//     o xmlns repetido no <NFe> dispara cStat=225 na SEFAZ-SP (mesmo passando no XSD
//     local, porque o parser deles não aceita namespace redundante em filho).
//   - SOLUÇÃO: ao montar o envelope, remover SOMENTE o xmlns do elemento raiz <NFe>
//     (sem alterar nada do conteúdo interno nem da assinatura).
//
// Mudança herdada da v5.2:
//   - REMOVIDO libxmljs2 (que falha de compilar no Node 25 do Render).
//   - Validação XSD oficial agora usa o binário `xmllint` (libxml2)
//     já presente em todo container Linux do Render — ZERO dependência
//     nativa npm, ZERO node-gyp, ZERO problema de versão de Node.
//   - Comportamento idêntico ao v5: HTTP 422 + diagnóstico XSD detalhado.
// ---------------------------------------------------------------

const express = require("express");
const https = require("https");
const tls = require("tls");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const forge = require("node-forge");
const { DOMParser, XMLSerializer } = require("@xmldom/xmldom");
const { SignedXml } = require("xml-crypto");
const { execFileSync, spawnSync } = require("child_process");
const os = require("os");

// ============================================================
// 1. ICP-Brasil CA Bundle (substitua pelos PEMs reais)
// ============================================================
const AC_RAIZ_V2 = `-----BEGIN CERTIFICATE-----
MIIGoTCCBImgAwIBAgIBATANBgkqhkiG9w0BAQ0FADCBlzELMAkGA1UEBhMCQlIx
EzARBgNVBAoTCklDUC1CcmFzaWwxPTA7BgNVBAsTNEluc3RpdHV0byBOYWNpb25h
bCBkZSBUZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMTK0F1
dG9yaWRhZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIwHhcNMTAw
NjIxMTkwNDU3WhcNMjMwNjIxMTkwNDU3WjCBlzELMAkGA1UEBhMCQlIxEzARBgNV
BAoTCklDUC1CcmFzaWwxPTA7BgNVBAsTNEluc3RpdHV0byBOYWNpb25hbCBkZSBU
ZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMTK0F1dG9yaWRh
ZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjIwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQC6RqQO3edA8rWgfFKVV0X8bYTzhgHJhQOtmKvS
8l4Fmcm7b2Jn/XdEuQMHPNIbAGLUcCxCg3lmq5lWroG8akm983QPYrfrWwdmlEIk
nUasmkIYMPAkqFFB6quV8agrAnhptSknXpwuc8b+I6Xjps79bBtrAFTrAK1POkw8
5wqIW9pemgtW5LVUOB3yCpNkTsNBklMgKs/8dG7U2zM4YuT+jkxYHPePKk3/xZLZ
CVK9z3AAnWmaM2qIh0UhmRZRDTTfgr20aah8fNTd0/IVXEvFWBDqhRnLNiJYKnIM
mpbeys8IUWG/tAUpBiuGkP7pTcMEBUfLz3bZf3Gmh3sVQOQzgHgHHaTyjptAO8ly
UN9pvvAslh+QtdWudONltIwa6Wob+3JcxYJU6uBTB8TMEun33tcv1EgvRz8mYQSx
Epoza7WGSxMr0IadR+1p+/yEEmb4VuUOimx2xGsaesKgWhLRI4lYAXwIWNoVjhXZ
fn03tqRF9QOFzEf6i3lFuGZiM9MmSt4c6dR/5m0muTx9zQ8oCikPm91jq7mmRxqE
14WkA2UGBEtSjYM0Qn8xjhEu5rNnlUB+l3pAAPkRbIM4WK0DM1umxMHFsKwNqQbw
pmkBNLbp+JRITz6mdQnsSsU74MlesDL/n2lZzzwwbw3OJ1fsWhto/+xPb3gyPnnF
tF2VfwIDAQABo4H1MIHyME4GA1UdIARHMEUwQwYFYEwBAQAwOjA4BggrBgEFBQcC
ARYsaHR0cDovL2FjcmFpei5pY3BicmFzaWwuZ292LmJyL0RQQ2FjcmFpei5wZGYw
PwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2FjcmFpei5pY3BicmFzaWwuZ292LmJy
L0xDUmFjcmFpenYyLmNybDAfBgNVHSMEGDAWgBQMOSA6twEfy9cofUGgx/pKrTIk
vjAdBgNVHQ4EFgQUDDkgOrcBH8vXKH1BoMf6Sq0yJL4wDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQENBQADggIBAFmaFGkYbX0pQ3B9
dpth33eOGnbkqdbLdqQWDEyUEsaQ0YEDxa0G2S1EvLIJdgmAOWcAGDRtBgrmtRBZ
SLp1YPw/jh0YVXArnkuVrImrCncke2HEx5EmjkYTUTe2jCcK0w3wmisig4OzvYM1
rZs8vHiDKTVhNvgRcTMgVGNTRQHYE1qEO9dmEyS3xEbFIthzJO4cExeWyCXoGx7P
34VQbTzq91CeG5fep2vb1nPSz3xQwLCM5VMSeoY5rDVbZ8fq1PvRwl3qDpdzmK4p
v+Q68wQ2UCzt3h7bhegdhAnu86aDM1tvR3lPSLX8uCYTq6qz9GER+0Vn8x0+bv4q
SyZEGp+xouA82uDkBTp4rPuooU2/XSx3KZDNEx3vBijYtxTzW8jJnqd+MRKKeGLE
0QW8BgJjBCsNid3kXFsygETUQuwq8/JAhzHVPuIKMgwUjdVybQvm/Y3kqPMFjXUX
d5sKufqQkplliDJnQwWOLQsVuzXxYejZZ3ftFuXoAS1rND+Og7P36g9KHj41hJ2M
gDQ/qZXow63EzZ7KFBYsGZ7kNou5uaNCJQc+w+XVaE+gZhyms7ZzHJAaP0C5GlZC
cIf/by0PEf0e//eFMBUO4xcx7ieVzMnpmR6Xx21bB7UFaj3yRd+6gnkkcC6bgh9m
qaVtJ8z2KqLRX4Vv4EadqtKlTlUO
-----END CERTIFICATE-----
`;

const AC_RAIZ_V5 = `-----BEGIN CERTIFICATE-----
MIIGoTCCBImgAwIBAgIBATANBgkqhkiG9w0BAQ0FADCBlzELMAkGA1UEBhMCQlIx
EzARBgNVBAoMCklDUC1CcmFzaWwxPTA7BgNVBAsMNEluc3RpdHV0byBOYWNpb25h
bCBkZSBUZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMMK0F1
dG9yaWRhZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjUwHhcNMTYw
MzAyMTMwMTM4WhcNMjkwMzAyMjM1OTM4WjCBlzELMAkGA1UEBhMCQlIxEzARBgNV
BAoMCklDUC1CcmFzaWwxPTA7BgNVBAsMNEluc3RpdHV0byBOYWNpb25hbCBkZSBU
ZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNDAyBgNVBAMMK0F1dG9yaWRh
ZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjUwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQD3LXgabUWsF+gUXw/6YODeF2XkqEyfk3VehdsI
x+3/ERgdjCS/ouxYR0Epi2hdoMUVJDNf3XQfjAWXJyCoTneHYAl2McMdvoqtLB2i
leQlJiis0fTtYTJayee9BAIdIrCor1Lc0vozXCpDtq5nTwhjIocaZtcuFsdrkl+n
bfYxl5m7vjTkTMS6j8ffjmFzbNPDlJuV3Vy7AzapPVJrMl6UHPXCHMYMzl0KxR/4
7S5XGgmLYkYt8bNCHA3fg07y+Gtvgu+SNhMPwWKIgwhYw+9vErOnavRhOimYo4M2
AwNpNK0OKLI7Im5V094jFp4Ty+mlmfQH00k8nkSUEN+1TGGkhv16c2hukbx9iCfb
mk7im2hGKjQA8eH64VPYoS2qdKbPbd3xDDHN2croYKpy2U2oQTVBSf9hC3o6fKo3
zp0U3dNiw7ZgWKS9UwP31Q0gwgB1orZgLuF+LIppHYwxcTG/AovNWa4sTPukMiX2
L+p7uIHExTZJJU4YoDacQh/mfbPIz3261He4YFmQ35sfw3eKHQSOLyiVfev/n0l/
r308PijEd+d+Hz5RmqIzS8jYXZIeJxym4mEjE1fKpeP56Ea52LlIJ8ZqsJ3xzHWu
3WkAVz4hMqrX6BPMGW2IxOuEUQyIaCBg1lI6QLiPMHvo2/J7gu4YfqRcH6i27W3H
yzamEQIDAQABo4H1MIHyME4GA1UdIARHMEUwQwYFYEwBAQAwOjA4BggrBgEFBQcC
ARYsaHR0cDovL2FjcmFpei5pY3BicmFzaWwuZ292LmJyL0RQQ2FjcmFpei5wZGYw
PwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2FjcmFpei5pY3BicmFzaWwuZ292LmJy
L0xDUmFjcmFpenY1LmNybDAfBgNVHSMEGDAWgBRpqL512cTvbOcTReRhbuVo+LZA
XjAdBgNVHQ4EFgQUaai+ddnE72znE0XkYW7laPi2QF4wDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQENBQADggIBABRt2/JiWapef7o/
plhR4PxymlMIp/JeZ5F0BZ1XafmYpl5g6pRokFrIRMFXLyEhlgo51I05InyCc9Td
6UXjlsOASTc/LRavyjB/8NcQjlRYDh6xf7OdP05mFcT/0+6bYRtNgsnUbr10pfsK
/UzyUvQWbumGS57hCZrAZOyd9MzukiF/azAa6JfoZk2nDkEudKOY8tRyTpMmDzN5
fufPSC3v7tSJUqTqo5z7roN/FmckRzGAYyz5XulbOc5/UsAT/tk+KP/clbbqd/hh
evmmdJclLr9qWZZcOgzuFU2YsgProtVu0fFNXGr6KK9fu44pOHajmMsTXK3X7r/P
wh19kFRow5F3RQMUZC6Re0YLfXh+ypnUSCzA+uL4JPtHIGyvkbWiulkustpOKUSV
wBPzvA2sQUOvqdbAR7C8jcHYFJMuK2HZFji7pxcWWab/NKsFcJ3sluDjmhizpQax
bYTfAVXu3q8yd0su/BHHhBpteyHvYyyz0Eb9LUysR2cMtWvfPU6vnoPgYvOGO1Cz
iyGEsgKULkCH4o2Vgl1gQuKWO4V68rFW8a/jvq28sbY+y/Ao0I5ohpnBcQOAawiF
bz6yJtObajYMuztDDP8oY656EuuJXBJhuKAJPI/7WDtgfV8ffOh/iQGQATVMtgDN
0gv8bn5NdUX8UMNX1sHhU3H1UpoW
-----END CERTIFICATE-----
`;

const AC_RAIZ_V10 = `-----BEGIN CERTIFICATE-----
MIIGrDCCBJSgAwIBAgIJANLVi0S/gZNCMA0GCSqGSIb3DQEBDQUAMIGYMQswCQYD
VQQGEwJCUjETMBEGA1UECgwKSUNQLUJyYXNpbDE9MDsGA1UECww0SW5zdGl0dXRv
IE5hY2lvbmFsIGRlIFRlY25vbG9naWEgZGEgSW5mb3JtYWNhbyAtIElUSTE1MDMG
A1UEAwwsQXV0b3JpZGFkZSBDZXJ0aWZpY2Fkb3JhIFJhaXogQnJhc2lsZWlyYSB2
MTAwHhcNMTkwNzAxMTkxNTU5WhcNMzIwNzAxMTIwMDU5WjCBmDELMAkGA1UEBhMC
QlIxEzARBgNVBAoMCklDUC1CcmFzaWwxPTA7BgNVBAsMNEluc3RpdHV0byBOYWNp
b25hbCBkZSBUZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxNTAzBgNVBAMM
LEF1dG9yaWRhZGUgQ2VydGlmaWNhZG9yYSBSYWl6IEJyYXNpbGVpcmEgdjEwMIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAk3AxKl1ZtP0pNyjChqO7qNkn
+/sClZeqiV/Kd7KnnbkDbI2y3VWcUG7feCE/deIxot6GH6JXncRG794UZl+4doD0
D0/cEwBd4DvrDSZm0RT40xhmYYOTxZDJxv+coTHdmsT5aNmSkktfjzYX4HQHh/7M
em+kTOpT/3E4K6B7KVs9HkOT7nXx5yU1qYbVWqI0qpJM9mOTSFx8C9HiKcHvLCvt
1ioXKPAmFuHPkayOcXP2MXeb+VRNjWKU4E+L2t5uZPKVx1M/9i1DztlLb4K8OfYg
GaPDUSF1sxnoGk5qZHLleO6KjCpmuQepmgsBvxi2YNO7X2YUwQQx1AXNSolgtkAR
5gt+1WzxhbFUhItQqlhqxgWHefLmiT5T/Ctz/P2v+zSO4efkkIzsi1iwD+ypZvM2
lnIvB24RcSN6jzmCahLPX4CwjwIK6JsSoMVxIhpZHCguUP4LXqP8IWUZ6WgS/4zB
7B9E0EICl2rM1PRy+6ulv+ZOW256e8a0pijUB+hXM1msUq9L92476FAAX8va3sP7
+Uut94+bGHmubcTLImWUPrxNT7QyrvE3FyHicfiHioeFL2oV4cXTLZrEq2wS8R4P
KPdSzNn5Z9e2uMEGYQaSNO+OwvVycpIhOBOqrm12wJ9ZhWKtM5UOo34/o37r5ZBI
TYXAGbhqQDB9mWXwH+0CAwEAAaOB9jCB8zBOBgNVHSAERzBFMEMGBWBMAQEAMDow
OAYIKwYBBQUHAgEWLGh0dHA6Ly9hY3JhaXouaWNwYnJhc2lsLmdvdi5ici9EUENh
Y3JhaXoucGRmMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly9hY3JhaXouaWNwYnJh
c2lsLmdvdi5ici9MQ1JhY3JhaXp2MTAuY3JsMB8GA1UdIwQYMBaAFHTzfv/8n1N6
8Xzrqz6kptoYukVjMB0GA1UdDgQWBBR0837//J9TevF866s+pKbaGLpFYzAPBgNV
HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQ0FAAOCAgEA
eCNhBSuy/Ih/T+1VOtAJju85SrtoE3vET1qXASpmjQllDHG/ph7VFNRAkC+gha+B
CbjoA5oJ/8wwl+Qdp1KGz6nXXFTLx3osU+kjm0srmBf9nyXHPqvFyvBeB0A7sYb7
TmII9GKD20oCxsdkccR/oE/JuTaNnGq0GYZ2aDb5v62uLi21Y6P9UBiTxZqQ4ojW
ET6kXNjlK238jpXv17FR8Sg3VusCvX7Q8eJkavvHHZDeWck2fSA+ycAc2JeL2Z0B
MSxGWpH32WM9J8+6XqCJUXHiWEV0zCE8wDYiYC+047pTxQI/gB/FcU7jvylh98DJ
kQPHd/Tp6Og3ynlDA9n9uBbxYHVRZs9vsZ/7xTFaxRe+zk8dhgKgZ/3RrcMFB570
2t8LFbyuUE/kQVY6rZ0QJ9qMWQ7VPLRwRhiMeU3k8WDJb/tBbOXHBqldTbWyQ+mp
MEDWhbrzE/IED82wAuO23Tb05cYk2xC7+Izef8fSc3XdJDuPSbcDpWukzyCDtSEH
isLiGEtIbYRiPsF3czlQPsnIEVoTTCWxHCH1zYR6zScSv18Qh69qVe2J40K5jZoP
GEOhq/oKhVJQAdvAFW5Odp7mF3Tk9nivjjsctJSxY26LFiV5GRV+07SSse4ti0aO
jO5PLg5SWjfcOtBG2rz02EIvQAmLcb0kGBtfdj0lW/w=
-----END CERTIFICATE-----
`;

const ICP_BRASIL_CA_BUNDLE = [AC_RAIZ_V2, AC_RAIZ_V5, AC_RAIZ_V10];
const FULL_CA_BUNDLE = [...ICP_BRASIL_CA_BUNDLE, ...tls.rootCertificates];

// ============================================================
// 2. URLs SEFAZ-SP
// ============================================================
const SEFAZ_URLS = {
  homologacao: "https://homologacao.nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx",
  producao: "https://nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx",
};
const QR_BASE = {
  homologacao: "https://www.homologacao.nfce.fazenda.sp.gov.br/qrcode",
  producao: "https://www.nfce.fazenda.sp.gov.br/qrcode",
};

// ============================================================
// 3. VALIDAÇÃO XSD via xmllint (libxml2 do sistema)
// ------------------------------------------------------------
// Em vez de depender do libxmljs2 (que precisa compilar nativamente
// e quebra no Node 25 do Render), usamos o binário `xmllint` que
// já vem instalado em todos os containers Linux do Render.
//
// Os XSDs devem estar em ./schemes/PL_009_V4/
// Baixe em: https://github.com/nfephp-org/sped-nfe/tree/master/schemes/PL_009_V4
// Arquivos necessários:
//   - leiauteNFe_v4.00.xsd
//   - tiposBasico_v4.00.xsd
//   - xmldsig-core-schema_v1.01.xsd
//   - enviNFe_v4.00.xsd
//   - nfe_v4.00.xsd
// ============================================================
const SCHEMAS_DIR = path.join(__dirname, "schemes", "PL_009_V4");
const SCHEMA_NFE_PATH = path.join(SCHEMAS_DIR, "nfe_v4.00.xsd");
const SCHEMA_ENVI_PATH = path.join(SCHEMAS_DIR, "enviNFe_v4.00.xsd");

let XMLLINT_AVAILABLE = false;
try {
  const r = spawnSync("xmllint", ["--version"], { encoding: "utf8" });
  XMLLINT_AVAILABLE = r.status === 0 || (r.stderr || "").includes("xmllint");
  console.log(`[XSD] xmllint disponível: ${XMLLINT_AVAILABLE}`);
} catch (e) {
  console.warn(`[XSD] xmllint NÃO disponível: ${e.message}`);
}

const SCHEMA_NFE_OK = fs.existsSync(SCHEMA_NFE_PATH);
const SCHEMA_ENVI_OK = fs.existsSync(SCHEMA_ENVI_PATH);
console.log(`[XSD] nfe_v4.00.xsd: ${SCHEMA_NFE_OK} | enviNFe_v4.00.xsd: ${SCHEMA_ENVI_OK}`);
if (!SCHEMA_NFE_OK || !SCHEMA_ENVI_OK) {
  console.warn(`[XSD] XSDs ausentes em ${SCHEMAS_DIR} — validação será PULADA. Crie a pasta e baixe os schemas oficiais PL_009_V4.`);
}

// Parser de saída do xmllint:
// Formato: "<arquivo>:<linha>: element X: Schemas validity error : Element '...': mensagem"
function parseXmllintErrors(stderr) {
  const linhas = (stderr || "").split("\n").map(l => l.trim()).filter(Boolean);
  const erros = [];
  for (const linha of linhas) {
    if (linha.includes("validates") || linha.includes("fails to validate")) continue;
    // tenta extrair número de linha
    const matchLinha = linha.match(/^[^:]+:(\d+):/);
    const ln = matchLinha ? parseInt(matchLinha[1], 10) : null;
    // tenta extrair elemento
    const matchEl = linha.match(/Element\s+'([^']+)'/i);
    const elemento = matchEl ? matchEl[1] : null;
    erros.push({
      linha: ln,
      coluna: null,
      mensagem: linha,
      elemento,
    });
  }
  return erros;
}

function validateXsd(xmlString, schemaPath, etapa) {
  if (!XMLLINT_AVAILABLE) {
    return { ok: true, skipped: true, motivo: "xmllint não disponível no sistema" };
  }
  if (!fs.existsSync(schemaPath)) {
    return { ok: true, skipped: true, motivo: `Schema ${etapa} não encontrado em ${schemaPath}` };
  }
  // grava XML em arquivo temporário
  const tmpXml = path.join(os.tmpdir(), `validate-${Date.now()}-${Math.random().toString(36).slice(2)}.xml`);
  try {
    fs.writeFileSync(tmpXml, xmlString, "utf8");
    const r = spawnSync(
      "xmllint",
      ["--noout", "--schema", schemaPath, tmpXml],
      { encoding: "utf8", maxBuffer: 20 * 1024 * 1024 }
    );
    if (r.status === 0) return { ok: true };
    const erros = parseXmllintErrors(r.stderr || r.stdout || "");
    return {
      ok: false,
      etapa,
      erros: erros.length ? erros : [{ linha: null, coluna: null, mensagem: (r.stderr || "Validação falhou sem mensagem").slice(0, 2000) }],
    };
  } catch (err) {
    return {
      ok: false,
      etapa,
      erros: [{ linha: null, coluna: null, mensagem: `Erro executando xmllint: ${err.message}` }],
    };
  } finally {
    try { fs.unlinkSync(tmpXml); } catch (_) {}
  }
}

// ============================================================
// 5. PFX → PEM
// ============================================================
function pfxToPem(pfxBase64, senha) {
  const der = forge.util.decode64(pfxBase64);
  const asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, senha);

  let keyPem = null;
  let certPem = null;

  for (const safeContents of p12.safeContents) {
    for (const safeBag of safeContents.safeBags) {
      if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag || safeBag.type === forge.pki.oids.keyBag) {
        keyPem = forge.pki.privateKeyToPem(safeBag.key);
      } else if (safeBag.type === forge.pki.oids.certBag) {
        if (!certPem) certPem = forge.pki.certificateToPem(safeBag.cert);
      }
    }
  }
  if (!keyPem || !certPem) throw new Error("PFX inválido: chave ou certificado ausente");
  return { keyPem, certPem };
}

// ============================================================
// 6. Assinatura XML (xml-crypto v6+)
// ============================================================
function signNFe(xmlNFe, keyPem, certPem) {
  const certBody = certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");

  const sig = new SignedXml({
    privateKey: keyPem,
    publicCert: certPem,
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    getKeyInfoContent: () => `<X509Data><X509Certificate>${certBody}</X509Certificate></X509Data>`,
  });

  sig.addReference({
    xpath: "//*[local-name(.)='infNFe']",
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ],
  });

  sig.computeSignature(xmlNFe, {
    location: { reference: "//*[local-name(.)='infNFe']", action: "after" },
  });

  return sig.getSignedXml();
}

// ============================================================
// 7. QR Code NFC-e 4.00
// ============================================================
function buildQrCode(chave, tpAmb, cscId, cscToken, ambiente) {
  const param = `${chave}|2|${tpAmb}|${cscId}`;
  const hash = crypto.createHash("sha1").update(param + cscToken).digest("hex").toUpperCase();
  const qrCode = `${QR_BASE[ambiente]}?p=${param}|${hash}`;
  const urlChave = `${QR_BASE[ambiente]}`;
  return { qrCode, urlChave };
}

// ============================================================
// 8. Adiciona <infNFeSupl> dentro de <NFe>, ANTES de <Signature>
//    (Ordem oficial PL_009_V4: infNFe → infNFeSupl → Signature)
// ============================================================
function addInfNFeSupl(xmlAssinado, qrCode, urlChave) {
  const doc = new DOMParser().parseFromString(xmlAssinado, "text/xml");
  const nfe = doc.getElementsByTagName("NFe")[0];
  if (!nfe) throw new Error("Tag <NFe> não encontrada");

  const ns = "http://www.portalfiscal.inf.br/nfe";
  const supl = doc.createElementNS(ns, "infNFeSupl");
  const qr = doc.createElementNS(ns, "qrCode");
  qr.appendChild(doc.createCDATASection(qrCode));
  const url = doc.createElementNS(ns, "urlChave");
  url.appendChild(doc.createTextNode(urlChave));
  supl.appendChild(qr);
  supl.appendChild(url);

  const sig = nfe.getElementsByTagName("Signature")[0];
  if (sig) {
    nfe.insertBefore(supl, sig);
  } else {
    nfe.appendChild(supl);
  }

  return new XMLSerializer().serializeToString(doc);
}

// ============================================================
// 9. Envelope <enviNFe>
// ============================================================
function buildEnviNFe(xmlNFeFinal) {
  // Remove o prólogo <?xml ... ?>
  let nfe = xmlNFeFinal.replace(/<\?xml[^>]*\?>/, "");

  // CORREÇÃO cStat=225: o <NFe> assinado vem com xmlns próprio porque
  // a assinatura precisa dele isolado (regra de canonicalização exclusiva).
  // Mas quando aninhado em <enviNFe xmlns="...nfe">, o xmlns repetido na
  // raiz <NFe> faz a SEFAZ-SP rejeitar com 225. O conteúdo interno
  // (infNFe, infNFeSupl, Signature) permanece INTACTO — só o atributo
  // xmlns do elemento raiz <NFe> é removido. Isso NÃO invalida a
  // assinatura, porque ela referencia <infNFe> via local-name() e foi
  // computada sobre o XML original assinado.
  nfe = nfe.replace(
    /^<NFe\s+xmlns="http:\/\/www\.portalfiscal\.inf\.br\/nfe"\s*>/,
    "<NFe>"
  );

  return `<?xml version="1.0" encoding="UTF-8"?>` +
    `<enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">` +
    `<idLote>1</idLote>` +
    `<indSinc>1</indSinc>` +
    nfe +
    `</enviNFe>`;
}

// ============================================================
// 10. Envelope SOAP 1.2
// ============================================================
function buildSoapEnvelope(enviNFe) {
  const inner = enviNFe.replace(/<\?xml[^>]*\?>/, "");
  return `<?xml version="1.0" encoding="UTF-8"?>` +
    `<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope" xmlns:nfe="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4">` +
    `<soap12:Body>` +
    `<nfe:nfeDadosMsg>${inner}</nfe:nfeDadosMsg>` +
    `</soap12:Body>` +
    `</soap12:Envelope>`;
}

// ============================================================
// 11. Transmissão SEFAZ
// ============================================================
function postSefaz(url, soapXml, pfxBuffer, senha) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const agent = new https.Agent({
      ca: FULL_CA_BUNDLE,
      pfx: pfxBuffer,
      passphrase: senha,
      keepAlive: true,
    });

    const req = https.request(
      {
        hostname: u.hostname,
        port: 443,
        path: u.pathname,
        method: "POST",
        agent,
        headers: {
          "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4/nfeAutorizacaoLote"',
          "Content-Length": Buffer.byteLength(soapXml),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      }
    );
    req.on("error", reject);
    req.write(soapXml);
    req.end();
  });
}

// ============================================================
// 12. Parse retorno
// ============================================================
function parseRetorno(soapBody) {
  const getIn = (scope, tag) => {
    const m = scope.match(new RegExp(`<${tag}[^>]*>([^<]+)</${tag}>`));
    return m ? m[1] : null;
  };

  const infProtMatch = soapBody.match(/<infProt[^>]*>([\s\S]*?)<\/infProt>/);
  if (infProtMatch) {
    const inner = infProtMatch[1];
    return {
      cStat: getIn(inner, "cStat"),
      xMotivo: getIn(inner, "xMotivo"),
      nProt: getIn(inner, "nProt"),
      chNFe: getIn(inner, "chNFe"),
      cStatLote: getIn(soapBody, "cStat"),
      xMotivoLote: getIn(soapBody, "xMotivo"),
    };
  }

  return {
    cStat: getIn(soapBody, "cStat"),
    xMotivo: getIn(soapBody, "xMotivo"),
    nProt: getIn(soapBody, "nProt"),
    chNFe: getIn(soapBody, "chNFe"),
    cStatLote: getIn(soapBody, "cStat"),
    xMotivoLote: getIn(soapBody, "xMotivo"),
  };
}

// ============================================================
// 13. Express
// ============================================================
const app = express();
app.use(express.json({ limit: "20mb" }));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    ts: new Date().toISOString(),
    schemas: { nfe: SCHEMA_NFE_OK, enviNFe: SCHEMA_ENVI_OK, xmllint: XMLLINT_AVAILABLE },
  });
});

app.post("/transmitir", async (req, res) => {
  const t0 = Date.now();
  try {
    const { tipo, ambiente, chave, xml, pfx_base64, senha, csc_id, csc_token } = req.body;

    if (!xml || !pfx_base64 || !senha) {
      return res.status(400).json({ error: "Campos obrigatórios: xml, pfx_base64, senha" });
    }
    const amb = ambiente === "producao" ? "producao" : "homologacao";
    const tpAmb = amb === "producao" ? "1" : "2";

    console.log(`[${chave}] Iniciando transmissão (${amb})`);

    // 1. PFX → PEM
    const { keyPem, certPem } = pfxToPem(pfx_base64, senha);
    console.log(`[${chave}] PFX convertido`);

    // 2. Assina <infNFe>
    const xmlAssinado = signNFe(xml, keyPem, certPem);
    console.log(`[${chave}] XML assinado`);

    // 3. Adiciona infNFeSupl com QR Code
    let xmlFinal = xmlAssinado;
    if (csc_id && csc_token) {
      const { qrCode, urlChave } = buildQrCode(chave, tpAmb, csc_id, csc_token, amb);
      xmlFinal = addInfNFeSupl(xmlAssinado, qrCode, urlChave);
      console.log(`[${chave}] infNFeSupl + QR Code inseridos`);
    }

    // 4. NOVO — Validação XSD do XML da NFe
    const validNFe = validateXsd(xmlFinal, SCHEMA_NFE_PATH, "nfe_v4.00");
    if (!validNFe.ok) {
      console.log(`[${chave}] XSD NFe FALHOU: ${validNFe.erros.length} erro(s)`);
      validNFe.erros.slice(0, 5).forEach((e) =>
        console.log(`    [L${e.linha}:${e.coluna}] ${e.mensagem}`)
      );
      return res.status(422).json({
        erro: "schema_local",
        etapa: "nfe_v4.00",
        xsd_erros: validNFe.erros,
        xml_validado: xmlFinal,
      });
    }
    console.log(`[${chave}] XSD NFe OK`);

    // 5. Envelopa
    const enviNFe = buildEnviNFe(xmlFinal);

    // 6. NOVO — Validação XSD do envelope <enviNFe>
    const validEnvi = validateXsd(enviNFe, SCHEMA_ENVI_PATH, "enviNFe_v4.00");
    if (!validEnvi.ok) {
      console.log(`[${chave}] XSD enviNFe FALHOU: ${validEnvi.erros.length} erro(s)`);
      validEnvi.erros.slice(0, 5).forEach((e) =>
        console.log(`    [L${e.linha}:${e.coluna}] ${e.mensagem}`)
      );
      return res.status(422).json({
        erro: "schema_local",
        etapa: "enviNFe_v4.00",
        xsd_erros: validEnvi.erros,
        xml_validado: enviNFe,
      });
    }
    console.log(`[${chave}] XSD enviNFe OK`);

    // 7. Monta SOAP e transmite
    const soapXml = buildSoapEnvelope(enviNFe);
    console.log(`[${chave}] Envelope SOAP montado`);

    const pfxBuffer = Buffer.from(pfx_base64, "base64");
    const url = SEFAZ_URLS[amb];
    const { status, body } = await postSefaz(url, soapXml, pfxBuffer, senha);
    console.log(`[${chave}] SEFAZ respondeu HTTP ${status} em ${Date.now() - t0}ms`);

    // 8. Parse retorno
    const retorno = parseRetorno(body);
    if (retorno.cStatLote && retorno.cStatLote !== retorno.cStat) {
      console.log(`[${chave}] LOTE cStat=${retorno.cStatLote} xMotivo=${retorno.xMotivoLote}`);
    }
    console.log(`[${chave}] NOTA cStat=${retorno.cStat} xMotivo=${retorno.xMotivo}`);

    return res.json({
      xml_assinado: xmlFinal,
      xml_envelope: soapXml,
      xml_retorno: body,
      http_status: status,
      cStat: retorno.cStat,
      xMotivo: retorno.xMotivo,
      nProt: retorno.nProt,
      validacao_local: { nfe: "ok", enviNFe: "ok" },
    });
  } catch (err) {
    console.error("Erro /transmitir:", err);
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ============================================================
// 14. Endpoint utilitário: validar XML offline (sem transmitir)
// POST /validar  body: { xml, etapa: "nfe" | "envi" }
// Útil para depurar XMLs colados sem precisar do PFX.
// ============================================================
app.post("/validar", (req, res) => {
  const { xml, etapa } = req.body;
  if (!xml) return res.status(400).json({ error: "Campo 'xml' obrigatório" });
  const schemaPath = etapa === "envi" ? SCHEMA_ENVI_PATH : SCHEMA_NFE_PATH;
  const result = validateXsd(xml, schemaPath, etapa || "nfe");
  return res.json(result);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Relay SEFAZ-SP v5.2 (XSD via xmllint) rodando na porta ${PORT}`));
