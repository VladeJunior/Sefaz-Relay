// SEFAZ Relay v2 - NFC-e 4.00 SP
// Recebe XML <NFe> limpo, assina, monta QR Code, envelopa e transmite.
// Stateless: não armazena certificado.

const express = require('express');
const forge = require('node-forge');
const { SignedXml } = require('xml-crypto');
const { DOMParser, XMLSerializer } = require('@xmldom/xmldom');
const xpath = require('xpath');
const https = require('https');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
app.use(express.json({ limit: '10mb' }));

const RELAY_TOKEN = process.env.RELAY_TOKEN;
if (!RELAY_TOKEN) console.warn('⚠️  RELAY_TOKEN não definido!');

// --- Auth middleware ---
app.use((req, res, next) => {
  if (req.path === '/health') return next();
  const auth = req.headers.authorization || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!RELAY_TOKEN || token !== RELAY_TOKEN) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  next();
});

app.get('/health', (_, res) => res.json({ ok: true, ts: Date.now() }));

// Endpoints SEFAZ-SP NFC-e 4.00
const ENDPOINTS = {
  '1': 'https://nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx',
  '2': 'https://homologacao.nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx',
};
const QR_BASES = {
  '1': 'https://www.nfce.fazenda.sp.gov.br/NFCeConsultaPublica/Paginas/ConsultaQRCode.aspx',
  '2': 'https://www.homologacao.nfce.fazenda.sp.gov.br/NFCeConsultaPublica/Paginas/ConsultaQRCode.aspx',
};
const URL_CHAVE = {
  '1': 'https://www.nfce.fazenda.sp.gov.br/NFCeConsultaPublica/Paginas/ConsultaNFCe.aspx',
  '2': 'https://www.homologacao.nfce.fazenda.sp.gov.br/NFCeConsultaPublica/Paginas/ConsultaNFCe.aspx',
};

app.post('/transmitir', async (req, res) => {
  try {
    const { tipo, ambiente, chave, xml, pfx_base64, senha, csc_id, csc_token } = req.body;

    if (tipo !== 'autorizacao') return res.status(400).json({ error: 'tipo não suportado' });
    if (!xml || !pfx_base64 || !senha || !chave) {
      return res.status(400).json({ error: 'parâmetros obrigatórios ausentes' });
    }
    const amb = String(ambiente);
    if (!ENDPOINTS[amb]) return res.status(400).json({ error: 'ambiente inválido' });

    // 1. Extrair PEM do PFX
    const { keyPem, certPem, certBase64 } = extractPem(pfx_base64, senha);

    // 2. Assinar infNFe
    const xmlAssinado = signNFe(xml, chave, keyPem, certPem, certBase64);

    // 3. Calcular QR Code e inserir infNFeSupl APÓS Signature
    const qrUrl = buildQrCode(chave, amb, csc_id, csc_token);
    const xmlComSupl = inserirInfNFeSupl(xmlAssinado, qrUrl, URL_CHAVE[amb]);

    // 4. Envelopar em enviNFe
    const enviNFe = `<enviNFe versao="4.00" xmlns="http://www.portalfiscal.inf.br/nfe"><idLote>${Date.now() % 1000000000000000}</idLote><indSinc>1</indSinc>${stripXmlDecl(xmlComSupl)}</enviNFe>`;

    // 5. SOAP 1.2
    const soapEnvelope = `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body><nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4">${enviNFe}</nfeDadosMsg></soap:Body></soap:Envelope>`;

    // 6. mTLS POST
    const pfxBuffer = Buffer.from(pfx_base64, 'base64');
    const httpsAgent = new https.Agent({ pfx: pfxBuffer, passphrase: senha, rejectUnauthorized: true });

    const sefazResp = await axios.post(ENDPOINTS[amb], soapEnvelope, {
      httpsAgent,
      headers: { 'Content-Type': 'application/soap+xml; charset=utf-8' },
      timeout: 60000,
      validateStatus: () => true,
    });

    const xmlRetorno = typeof sefazResp.data === 'string' ? sefazResp.data : String(sefazResp.data);

    // 7. Extrair cStat / nProt / xMotivo
    const cStat = extractTag(xmlRetorno, 'cStat');
    const xMotivo = extractTag(xmlRetorno, 'xMotivo');
    const nProt = extractTag(xmlRetorno, 'nProt');

    return res.json({
      xml_assinado: xmlComSupl,
      xml_envelope: soapEnvelope,
      xml_retorno: xmlRetorno,
      cStat,
      xMotivo,
      nProt,
      http_status: sefazResp.status,
    });
  } catch (err) {
    console.error('Erro /transmitir:', err);
    return res.status(500).json({ error: err.message ?? String(err) });
  }
});

// --- Helpers ---

function extractPem(pfxBase64, senha) {
  const der = forge.util.decode64(pfxBase64);
  const asn1 = forge.asn1.fromDer(der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, senha);

  let keyObj = null;
  let certObj = null;

  p12.safeContents.forEach(sc => {
    sc.safeBags.forEach(bag => {
      if (bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag) {
        keyObj = bag.key;
      } else if (bag.type === forge.pki.oids.certBag) {
        // pega o certificado do titular (não da AC)
        if (!certObj || (bag.cert.subject.getField('CN')?.value || '').includes(':')) {
          certObj = bag.cert;
        }
      }
    });
  });

  if (!keyObj || !certObj) throw new Error('PFX inválido: chave ou certificado não encontrados');

  const keyPem = forge.pki.privateKeyToPem(keyObj);
  const certPem = forge.pki.certificateToPem(certObj);
  const certBase64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');

  return { keyPem, certPem, certBase64 };
}

function signNFe(xmlString, chave, keyPem, certPem, certBase64) {
  const sig = new SignedXml({
    privateKey: keyPem,
    publicCert: certPem,
    canonicalizationAlgorithm: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
  });

  sig.addReference({
    xpath: "//*[local-name(.)='infNFe']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
    ],
    digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
    uri: `#NFe${chave}`,
  });

  // KeyInfo customizado com X509Certificate
  sig.getKeyInfoContent = () => `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`;

  sig.computeSignature(xmlString, {
    location: { reference: "//*[local-name(.)='infNFe']", action: 'after' },
  });

  return sig.getSignedXml();
}

function buildQrCode(chave, ambiente, cscId, cscToken) {
  const cIdToken = String(cscId).padStart(6, '0');
  const param = `${chave}|2|${ambiente}|${cIdToken}`;
  const hash = crypto.createHash('sha1').update(param + cscToken).digest('hex').toUpperCase();
  return `${QR_BASES[ambiente]}?p=${param}|${hash}`;
}

function inserirInfNFeSupl(xmlAssinado, qrUrl, urlChave) {
  const doc = new DOMParser().parseFromString(xmlAssinado, 'text/xml');
  const nfeNode = doc.documentElement; // <NFe>
  const supl = doc.createElementNS('http://www.portalfiscal.inf.br/nfe', 'infNFeSupl');
  const qrEl = doc.createElementNS('http://www.portalfiscal.inf.br/nfe', 'qrCode');
  qrEl.appendChild(doc.createCDATASection(qrUrl));
  supl.appendChild(qrEl);
  const urlEl = doc.createElementNS('http://www.portalfiscal.inf.br/nfe', 'urlChave');
  urlEl.appendChild(doc.createTextNode(urlChave));
  supl.appendChild(urlEl);
  // Append como ÚLTIMO filho de <NFe> — Signature já está em segundo, então fica
  // a ordem: infNFe → Signature → infNFeSupl ✅
  nfeNode.appendChild(supl);
  return new XMLSerializer().serializeToString(doc);
}

function stripXmlDecl(xml) {
  return xml.replace(/^<\?xml[^>]*\?>\s*/, '');
}

function extractTag(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`));
  return m ? m[1] : null;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SEFAZ Relay v2 ouvindo em ${PORT}`));
