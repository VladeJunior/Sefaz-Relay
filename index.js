// SEFAZ-SP NFC-e Relay v5 — Validação XSD oficial antes de transmitir
// ---------------------------------------------------------------
// Mudança chave em relação à v4:
//   - Validação XSD oficial (PL_009_V4) ANTES de enviar para a SEFAZ.
//   - Quando o XML não passa no schema, devolve HTTP 422 com diagnóstico
//     contendo o ELEMENTO EXATO que quebrou (linha, coluna, mensagem).
//   - Com isso a aplicação para de receber "cStat 225" genérico e passa
//     a saber exatamente qual nó/atributo está inválido.
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
const libxml = require("libxmljs2");

// ============================================================
// 1. ICP-Brasil CA Bundle (substitua pelos PEMs reais)
// ============================================================
const AC_RAIZ_V2 = `-----BEGIN CERTIFICATE-----
COLE_AQUI_O_PEM_DA_AC_RAIZ_V2
-----END CERTIFICATE-----
`;

const AC_RAIZ_V5 = `-----BEGIN CERTIFICATE-----
COLE_AQUI_O_PEM_DA_AC_RAIZ_V5
-----END CERTIFICATE-----
`;

const AC_RAIZ_V10 = `-----BEGIN CERTIFICATE-----
COLE_AQUI_O_PEM_DA_AC_RAIZ_V10
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
// 3. CARREGAMENTO DOS SCHEMAS XSD OFICIAIS (PL_009_V4)
// ------------------------------------------------------------
// Os arquivos devem estar em ./schemes/PL_009_V4/
// Baixe em: https://github.com/nfephp-org/sped-nfe/tree/master/schemes/PL_009_V4
// Arquivos necessários:
//   - leiauteNFe_v4.00.xsd       (define <NFe>)
//   - tiposBasico_v4.00.xsd
//   - xmldsig-core-schema_v1.01.xsd
//   - enviNFe_v4.00.xsd          (define <enviNFe>)
//   - nfe_v4.00.xsd
// ============================================================
const SCHEMAS_DIR = path.join(__dirname, "schemes", "PL_009_V4");

let SCHEMA_NFE = null;
let SCHEMA_ENVI = null;

function loadSchema(filename) {
  const fullPath = path.join(SCHEMAS_DIR, filename);
  if (!fs.existsSync(fullPath)) {
    console.warn(`[SCHEMA] Arquivo não encontrado: ${fullPath} — validação XSD desabilitada para este schema.`);
    return null;
  }
  try {
    // libxmljs2 resolve includes relativos automaticamente quando passamos baseUrl
    const xsdContent = fs.readFileSync(fullPath, "utf8");
    return libxml.parseXml(xsdContent, { baseUrl: SCHEMAS_DIR + path.sep });
  } catch (err) {
    console.error(`[SCHEMA] Erro carregando ${filename}:`, err.message);
    return null;
  }
}

function loadAllSchemas() {
  if (!fs.existsSync(SCHEMAS_DIR)) {
    console.warn(`[SCHEMA] Diretório ${SCHEMAS_DIR} não existe. Validação XSD DESABILITADA. Crie o diretório e baixe os XSDs.`);
    return;
  }
  SCHEMA_NFE = loadSchema("nfe_v4.00.xsd");
  SCHEMA_ENVI = loadSchema("enviNFe_v4.00.xsd");
  console.log(`[SCHEMA] NFe carregado: ${!!SCHEMA_NFE} | enviNFe carregado: ${!!SCHEMA_ENVI}`);
}

loadAllSchemas();

// ============================================================
// 4. Validação XSD genérica
// ------------------------------------------------------------
// Retorna:
//   - { ok: true } se passar (ou se schema não estiver carregado)
//   - { ok: false, etapa, erros: [{ linha, coluna, mensagem, elemento }] }
// ============================================================
function validateXsd(xmlString, schema, etapa) {
  if (!schema) {
    return { ok: true, skipped: true, motivo: `Schema ${etapa} não carregado` };
  }
  try {
    const doc = libxml.parseXml(xmlString);
    const valid = doc.validate(schema);
    if (valid) return { ok: true };

    const erros = (doc.validationErrors || []).map((e) => ({
      linha: e.line,
      coluna: e.column,
      nivel: e.level,
      codigo: e.code,
      dominio: e.domain,
      mensagem: (e.message || "").trim(),
      // Tenta extrair o elemento entre aspas da mensagem ("Element 'X': ...")
      elemento: (() => {
        const m = (e.message || "").match(/Element\s+'([^']+)'/i);
        return m ? m[1] : null;
      })(),
    }));
    return { ok: false, etapa, erros };
  } catch (err) {
    return {
      ok: false,
      etapa,
      erros: [{ linha: null, coluna: null, mensagem: `Falha ao parsear XML: ${err.message}` }],
    };
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
  return `<?xml version="1.0" encoding="UTF-8"?>` +
    `<enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">` +
    `<idLote>1</idLote>` +
    `<indSinc>1</indSinc>` +
    xmlNFeFinal.replace(/<\?xml[^>]*\?>/, "") +
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
    schemas: { nfe: !!SCHEMA_NFE, enviNFe: !!SCHEMA_ENVI },
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
    const validNFe = validateXsd(xmlFinal, SCHEMA_NFE, "nfe_v4.00");
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
    const validEnvi = validateXsd(enviNFe, SCHEMA_ENVI, "enviNFe_v4.00");
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
  const schema = etapa === "envi" ? SCHEMA_ENVI : SCHEMA_NFE;
  const result = validateXsd(xml, schema, etapa || "nfe");
  return res.json(result);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Relay SEFAZ-SP v5 (com validação XSD) rodando na porta ${PORT}`));
