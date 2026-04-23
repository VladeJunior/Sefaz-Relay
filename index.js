// =============================================================================
// NFC-e Relay SP — Render
// =============================================================================

const express = require("express");
const https = require("https");
const tls = require("tls");
const crypto = require("crypto");
const forge = require("node-forge");
const { DOMParser, XMLSerializer } = require("@xmldom/xmldom");
const { SignedXml } = require("xml-crypto");

const app = express();
app.use(express.json({ limit: "20mb" }));

// =============================================================================
// CA BUNDLE — ICP-Brasil
// SUBSTITUA o conteudo abaixo pelos PEMs reais das raizes ICP-Brasil v2/v5/v10
// Baixe em: https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz
// =============================================================================
const ICP_BRASIL_CA = `
-----BEGIN CERTIFICATE-----
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
-----BEGIN CERTIFICATE-----
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
-----BEGIN CERTIFICATE-----
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
`.trim();

const CA_BUNDLE = [ICP_BRASIL_CA, ...tls.rootCertificates];

// =============================================================================
// URLs SEFAZ-SP
// =============================================================================
const SEFAZ_URLS = {
  autorizacao: {
    1: "https://nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx",
    2: "https://homologacao.nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx",
  },
  qrcode: {
    1: "https://www.nfce.fazenda.sp.gov.br/qrcode",
    2: "https://www.homologacao.nfce.fazenda.sp.gov.br/qrcode",
  },
  consultaChave: {
    1: "https://www.nfce.fazenda.sp.gov.br/consulta",
    2: "https://www.homologacao.nfce.fazenda.sp.gov.br/consulta",
  },
};

// =============================================================================
// Auth Bearer token
// =============================================================================
const RELAY_TOKEN = process.env.RELAY_TOKEN || process.env.SEFAZ_RELAY_TOKEN || "";

function checkAuth(req, res) {
  if (!RELAY_TOKEN) return true;
  const auth = req.headers["authorization"] || "";
  const expected = `Bearer ${RELAY_TOKEN}`;
  if (auth !== expected) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

// =============================================================================
// PFX -> PEM
// =============================================================================
function pfxToPem(pfxBase64, senha) {
  const pfxDer = forge.util.decode64(pfxBase64);
  const pfxAsn1 = forge.asn1.fromDer(pfxDer);
  const p12 = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, senha);

  let keyPem = null;
  let certPem = null;
  const caCerts = [];

  for (const safe of p12.safeContents) {
    for (const bag of safe.safeBags) {
      if (bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag) {
        keyPem = forge.pki.privateKeyToPem(bag.key);
      } else if (bag.type === forge.pki.oids.certBag) {
        const pem = forge.pki.certificateToPem(bag.cert);
        if (!certPem) certPem = pem;
        else caCerts.push(pem);
      }
    }
  }

  if (!keyPem || !certPem) {
    throw new Error("PFX nao contem chave privada ou certificado.");
  }

  return { keyPem, certPem, caCerts };
}

// =============================================================================
// Assinar <infNFe>
// =============================================================================
function signNFe(xmlNFe, keyPem, certPem) {
  const certB64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");

  const sig = new SignedXml({
    privateKey: keyPem,
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    getKeyInfoContent: () =>
      `<X509Data><X509Certificate>${certB64}</X509Certificate></X509Data>`,
  });

  sig.addReference({
    xpath: "//*[local-name(.)='infNFe']",
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ],
    uri: `#${extractInfNFeId(xmlNFe)}`,
  });

  sig.computeSignature(xmlNFe, {
    location: { reference: "//*[local-name(.)='infNFe']", action: "after" },
  });

  return sig.getSignedXml();
}

function extractInfNFeId(xml) {
  const m = xml.match(/<infNFe[^>]*\bId="([^"]+)"/);
  if (!m) throw new Error("infNFe sem atributo Id.");
  return m[1];
}

// =============================================================================
// QR Code NFC-e 4.00 (tpEmis=1)
// paramUrl   = chNFe|nVersao|tpAmb               (SEM cIdToken)
// stringHash = chNFe|nVersao|tpAmb|cIdToken|CSC  (cIdToken+CSC so no hash)
// =============================================================================
function buildQrCode({ chave, ambiente, csc_id, csc_token, qrBase }) {
  const tpAmb = String(ambiente);
  const nVersao = "2";
  const cIdToken = String(csc_id).padStart(6, "0");
  const paramUrl = `${chave}|${nVersao}|${tpAmb}`;
  const stringHash = `${chave}|${nVersao}|${tpAmb}|${cIdToken}|${csc_token}`;
  const hash = crypto.createHash("sha1").update(stringHash).digest("hex").toUpperCase();
  return `${qrBase}?p=${paramUrl}|${hash}`;
}

// =============================================================================
// inserir <infNFeSupl> DEPOIS de <Signature>
// Ordem correta NFC-e 4.00: infNFe -> Signature -> infNFeSupl
// =============================================================================
function insertInfNFeSupl(xmlNFeAssinado, qrCodeUrl, urlChave) {
  const doc = new DOMParser().parseFromString(xmlNFeAssinado, "text/xml");
  const nfe = doc.getElementsByTagName("NFe")[0];
  if (!nfe) throw new Error("Tag <NFe> nao encontrada para inserir infNFeSupl.");

  const supl = doc.createElement("infNFeSupl");
  const qr = doc.createElement("qrCode");
  qr.appendChild(doc.createCDATASection(qrCodeUrl));
  const url = doc.createElement("urlChave");
  url.appendChild(doc.createTextNode(urlChave));
  supl.appendChild(qr);
  supl.appendChild(url);

  const signature = nfe.getElementsByTagName("Signature")[0];
  if (signature) {
    if (signature.nextSibling) {
      nfe.insertBefore(supl, signature.nextSibling);
    } else {
      nfe.appendChild(supl);
    }
  } else {
    nfe.appendChild(supl);
  }

  return new XMLSerializer().serializeToString(doc);
}

// =============================================================================
// Envelopes enviNFe + SOAP 1.2
// =============================================================================
function buildEnviNFe(xmlNFeAssinadoComSupl, idLote) {
  return `<?xml version="1.0" encoding="UTF-8"?>` +
    `<enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">` +
    `<idLote>${idLote}</idLote>` +
    `<indSinc>1</indSinc>` +
    `${xmlNFeAssinadoComSupl.replace(/<\?xml[^>]*\?>/, "")}` +
    `</enviNFe>`;
}

function buildSoapEnvelope(enviNFeXml) {
  return `<?xml version="1.0" encoding="UTF-8"?>` +
    `<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope" xmlns:nfe="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4">` +
    `<soap12:Body>` +
    `<nfe:nfeDadosMsg>${enviNFeXml.replace(/<\?xml[^>]*\?>/, "")}</nfe:nfeDadosMsg>` +
    `</soap12:Body>` +
    `</soap12:Envelope>`;
}

// =============================================================================
// POST mTLS para SEFAZ
// =============================================================================
function postSefaz({ url, body, pfxBase64, senha }) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const agent = new https.Agent({
      pfx: Buffer.from(pfxBase64, "base64"),
      passphrase: senha,
      ca: CA_BUNDLE,
      keepAlive: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    });

    const req = https.request(
      {
        host: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method: "POST",
        agent,
        headers: {
          "Content-Type": "application/soap+xml; charset=utf-8",
          "Content-Length": Buffer.byteLength(body, "utf8"),
          "SOAPAction":
            "http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4/nfeAutorizacaoLote",
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      }
    );

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// =============================================================================
// Extrair cStat / nProt / xMotivo
// =============================================================================
function parseRetorno(xmlRetorno) {
  const grab = (tag) => {
    const m = xmlRetorno.match(new RegExp(`<${tag}[^>]*>([^<]+)</${tag}>`));
    return m ? m[1] : null;
  };
  return {
    cStat: grab("cStat"),
    xMotivo: grab("xMotivo"),
    nProt: grab("nProt"),
    chNFe: grab("chNFe"),
  };
}

// =============================================================================
// Endpoint: /health
// =============================================================================
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    ts: Date.now(),
    ca_bundle_size: CA_BUNDLE.length,
    icp_brasil_loaded:
      ICP_BRASIL_CA.includes("BEGIN CERTIFICATE") &&
      !ICP_BRASIL_CA.includes("COLE_AQUI"),
  });
});

// =============================================================================
// Endpoint: /transmitir
// =============================================================================
app.post("/transmitir", async (req, res) => {
  if (!checkAuth(req, res)) return;

  const t0 = Date.now();
  try {
    const {
      ambiente = 2,
      chave,
      xml,
      pfx_base64,
      senha,
      csc_id,
      csc_token,
    } = req.body || {};

    if (!xml || !pfx_base64 || !senha || !chave || !csc_id || !csc_token) {
      return res.status(400).json({ error: "Parametros obrigatorios ausentes." });
    }

    console.log(`[transmitir] inicio chave=${chave} ambiente=${ambiente}`);

    const { keyPem, certPem } = pfxToPem(pfx_base64, senha);
    console.log(`[transmitir] pfx convertido para pem`);

    const xmlAssinado = signNFe(xml, keyPem, certPem);
    console.log(`[transmitir] xml assinado`);

    const qrBase = SEFAZ_URLS.qrcode[ambiente];
    const urlChave = SEFAZ_URLS.consultaChave[ambiente];
    const qrCodeUrl = buildQrCode({ chave, ambiente, csc_id, csc_token, qrBase });
    const xmlAssinadoComSupl = insertInfNFeSupl(xmlAssinado, qrCodeUrl, urlChave);
    console.log(`[transmitir] infNFeSupl inserido apos Signature`);

    const idLote = String(Date.now()).slice(-15);
    const enviNFe = buildEnviNFe(xmlAssinadoComSupl, idLote);
    const soap = buildSoapEnvelope(enviNFe);

    const url = SEFAZ_URLS.autorizacao[ambiente];
    console.log(`[transmitir] enviando para ${url}`);
    const resp = await postSefaz({ url, body: soap, pfxBase64: pfx_base64, senha });
    console.log(`[transmitir] resposta sefaz status=${resp.status} (${Date.now() - t0}ms)`);

    const parsed = parseRetorno(resp.body);
    console.log(`[transmitir] cStat=${parsed.cStat} xMotivo=${parsed.xMotivo}`);

    return res.json({
      ok: true,
      xml_assinado: xmlAssinadoComSupl,
      xml_envelope: soap,
      xml_retorno: resp.body,
      http_status: resp.status,
      ...parsed,
    });
  } catch (err) {
    console.error(`[transmitir] erro:`, err);
    return res.status(500).json({
      error: err.message || String(err),
      code: err.code || null,
    });
  }
});

// =============================================================================
// Start
// =============================================================================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`NFC-e Relay rodando na porta ${PORT}`);
  console.log(`CA bundle: ${CA_BUNDLE.length} certificados (ICP-Brasil + sistema)`);
});
