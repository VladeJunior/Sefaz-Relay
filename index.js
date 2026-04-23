const express = require("express");
const https = require("https");
const forge = require("node-forge");
const { SignedXml } = require("xml-crypto");
const { DOMParser, XMLSerializer } = require("@xmldom/xmldom");

const app = express();
app.use(express.json({ limit: "10mb" }));

const RELAY_TOKEN = process.env.RELAY_TOKEN;
const PORT = process.env.PORT || 10000;

if (!RELAY_TOKEN) {
  console.error("ERRO: variável de ambiente RELAY_TOKEN não configurada.");
  process.exit(1);
}

// ---------- Health check (Render usa para manter o serviço acordado) ----------
app.get("/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// ---------- Auth middleware ----------
function checkToken(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (token !== RELAY_TOKEN) {
    return res.status(401).json({ error: "Token inválido." });
  }
  next();
}

// ---------- Extrai chave + cert do PFX ----------
function extractPfx(pfxBase64, senha) {
  const pfxDer = forge.util.decode64(pfxBase64);
  const pfxAsn1 = forge.asn1.fromDer(pfxDer);
  const p12 = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, senha);

  // Chave privada
  let privateKey = null;
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBagList = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
  if (keyBagList.length > 0) {
    privateKey = keyBagList[0].key;
  } else {
    const altBags = p12.getBags({ bagType: forge.pki.oids.keyBag });
    const altList = altBags[forge.pki.oids.keyBag] || [];
    if (altList.length > 0) privateKey = altList[0].key;
  }
  if (!privateKey) throw new Error("Chave privada não encontrada no PFX.");

  // Certificado
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certList = certBags[forge.pki.oids.certBag] || [];
  if (certList.length === 0) throw new Error("Certificado não encontrado no PFX.");
  const certificate = certList[0].cert;

  // PEM (para xml-crypto)
  const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
  const certPem = forge.pki.certificateToPem(certificate);

  // Base64 do cert (DER) para inserir no <X509Certificate>
  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes();
  const certBase64 = forge.util.encode64(certDer);

  return { privateKeyPem, certPem, certBase64 };
}

// ---------- Assina o XML conforme XMLDSig (NFe) ----------
function assinarXml(xml, privateKeyPem, certBase64, referenceId) {
  const sig = new SignedXml({
    privateKey: privateKeyPem,
    signatureAlgorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  });

  sig.addReference({
    xpath: `//*[local-name(.)='infNFe' and @Id='${referenceId}']`,
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ],
    digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
  });

  sig.getKeyInfoContent = () =>
    `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`;

  // Assina e insere a tag Signature DENTRO de <NFe>, após </infNFe>
  sig.computeSignature(xml, {
    location: {
      reference: "//*[local-name(.)='NFe']",
      action: "append",
    },
  });

  return sig.getSignedXml();
}

// ---------- Envelopa em SOAP e envia à SEFAZ via mTLS ----------
async function enviarSefaz({ xmlAssinado, ambiente, pfxBuffer, senha }) {
  // Endpoint NFC-e SP (NFeAutorizacao4)
  const url =
    ambiente === "1"
      ? "https://nfe.fazenda.sp.gov.br/ws/nfeautorizacao4.asmx"
      : "https://homologacao.nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx";

  const idLote = String(Date.now()).slice(-15);

  const soapEnvelope = `<?xml version="1.0" encoding="UTF-8"?><soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope" xmlns:nfe="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4"><soap12:Body><nfe:nfeDadosMsg><enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00"><idLote>${idLote}</idLote><indSinc>1</indSinc>${xmlAssinado.replace(/<\?xml[^?]*\?>/, "")}</enviNFe></nfe:nfeDadosMsg></soap12:Body></soap12:Envelope>`;

  const agent = new https.Agent({
    pfx: pfxBuffer,
    passphrase: senha,
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
  });

  const start = Date.now();
  const response = await new Promise((resolve, reject) => {
    const req = https.request(
      url,
      {
        method: "POST",
        agent,
        headers: {
          "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4/nfeAutorizacaoLote"',
          "Content-Length": Buffer.byteLength(soapEnvelope),
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString("utf-8"),
          })
        );
      }
    );
    req.on("error", reject);
    req.setTimeout(60000, () => req.destroy(new Error("Timeout SEFAZ (60s)")));
    req.write(soapEnvelope);
    req.end();
  });
  const tempo = Date.now() - start;

  // Parse simples do retorno
  const body = response.body || "";
  const cStat = (body.match(/<cStat>(\d+)<\/cStat>/) || [])[1] || "";
  const xMotivo = (body.match(/<xMotivo>([^<]+)<\/xMotivo>/) || [])[1] || "";
  const nProt = (body.match(/<nProt>(\d+)<\/nProt>/) || [])[1] || "";
  const nRec = (body.match(/<nRec>(\d+)<\/nRec>/) || [])[1] || "";

  return {
    httpStatus: response.status,
    cStat,
    xMotivo,
    nProt,
    nRec,
    soapEnvelope,
    xmlRetorno: body,
    tempoMs: tempo,
  };
}

// ---------- Endpoint principal ----------
app.post("/transmitir", checkToken, async (req, res) => {
  try {
    const { xml, pfx_base64, senha, ambiente, chave } = req.body || {};

    if (!xml || !pfx_base64 || !senha || !ambiente || !chave) {
      return res.status(400).json({
        error:
          "Campos obrigatórios: xml, pfx_base64, senha, ambiente, chave.",
      });
    }

    // 1. Extrai chave/cert do PFX
    const { privateKeyPem, certBase64 } = extractPfx(pfx_base64, senha);

    // 2. Assina o XML
    const referenceId = `NFe${chave}`;
    const xmlAssinado = assinarXml(xml, privateKeyPem, certBase64, referenceId);

    // 3. Envia à SEFAZ via mTLS
    const pfxBuffer = Buffer.from(pfx_base64, "base64");
    const resultado = await enviarSefaz({
      xmlAssinado,
      ambiente,
      pfxBuffer,
      senha,
    });

    return res.json({
      sucesso: resultado.cStat === "100" || resultado.cStat === "104",
      xml_assinado: xmlAssinado,
      soap_enviado: resultado.soapEnvelope,
      xml_retorno: resultado.xmlRetorno,
      cStat: resultado.cStat,
      xMotivo: resultado.xMotivo,
      nProt: resultado.nProt,
      nRec: resultado.nRec,
      http_status: resultado.httpStatus,
      tempo_ms: resultado.tempoMs,
    });
  } catch (err) {
    console.error("Erro /transmitir:", err);
    return res.status(500).json({
      error: err.message || "Erro interno no relay.",
      stack: process.env.NODE_ENV === "production" ? undefined : err.stack,
    });
  }
});

app.listen(PORT, () => {
  console.log(`SEFAZ relay rodando na porta ${PORT}`);
});
