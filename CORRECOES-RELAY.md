# Correções obrigatórias no relay (sefaz-relay) — NFC-e 4.00 SP

## Por que ainda dá Rejeição 225 (Falha no Schema XML)

O XML que sai da edge function agora vem **limpo** assim:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<NFe xmlns="http://www.portalfiscal.inf.br/nfe">
  <infNFe versao="4.00" Id="NFe...">
    ...
  </infNFe>
</NFe>
```

**Sem `<Signature>`. Sem `<infNFeSupl>`.** Isso é proposital: a ordem dos
elementos dentro de `<NFe>` é obrigatória pelo schema, e qualquer construção
prévia desses nós causa rejeição. O relay precisa montá-los na ordem correta.

## Ordem CORRETA dos filhos de `<NFe>` (NFC-e 4.00):

1. `<infNFe>` ← veio pronto da edge function
2. `<Signature>` ← o relay assina e insere AQUI, logo após `</infNFe>`
3. `<infNFeSupl>` ← o relay calcula QR Code e insere AQUI, depois da Signature

❌ A ordem `infNFe → infNFeSupl → Signature` (que estávamos usando) é
   INVÁLIDA pelo schema e gera cStat 225.

## Passos no relay, em ordem:

### 1. Assinar `<infNFe>`

Use `xml-crypto` com:
- **Reference URI**: `#NFe<chave>` (ex: `#NFe35260448...`)
- **Canonicalization**: `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
- **SignatureMethod**: `http://www.w3.org/2000/09/xmldsig#rsa-sha1`
- **DigestMethod**: `http://www.w3.org/2000/09/xmldsig#sha1`
- **Transforms**: enveloped-signature + c14n
- **KeyInfo**: incluir `X509Data > X509Certificate` (sem cabeçalho PEM, só base64)
- **InsertBefore / Location**: a `<Signature>` deve ficar como filho direto de
  `<NFe>`, **logo após `</infNFe>`**.

Exemplo com `xml-crypto`:

```js
const sig = new SignedXml({ privateKey: pem, publicCert: certPem });
sig.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
sig.signatureAlgorithm = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
sig.addReference({
  xpath: "//*[local-name(.)='infNFe']",
  transforms: [
    'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  ],
  digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
  uri: `#NFe${chave}`,
});
sig.computeSignature(xmlString, {
  location: { reference: "//*[local-name(.)='infNFe']", action: 'after' },
});
const xmlAssinado = sig.getSignedXml();
```

### 2. Calcular QR Code NFC-e 4.00

Para NFC-e SP, o QR Code é (sem CPF do destinatário ou com — varia o `cDest`):

```
param = chNFe|nVersao|tpAmb|cIdToken
hash  = SHA1_HEX_UPPER( param + CSC )
qrUrl = <baseSEFAZ>?p=param|hash
```

Onde:
- `chNFe`: 44 dígitos da chave
- `nVersao`: `2` (sempre, para NFC-e 4.00)
- `tpAmb`: `1` ou `2`
- `cIdToken`: o CSC ID com **6 dígitos** (zero-padded, ex: `000001`)
- `CSC`: o token literal (NÃO é o ID, é o "código segredo")

Base SEFAZ-SP:
- Produção: `https://www.nfce.fazenda.sp.gov.br/NFCeConsultaPublica/Paginas/ConsultaQRCode.aspx`
- Homolog:  `https://www.homologacao.nfce.fazenda.sp.gov.br/NFCeConsultaPublica/Paginas/ConsultaQRCode.aspx`

```js
const crypto = require('crypto');
const cIdToken = String(cscId).padStart(6, '0');
const param = `${chave}|2|${ambiente}|${cIdToken}`;
const hash = crypto.createHash('sha1').update(param + cscToken).digest('hex').toUpperCase();
const qrUrl = `${baseUrl}?p=${param}|${hash}`;
```

### 3. Inserir `<infNFeSupl>` APÓS a `<Signature>`

Como filho de `<NFe>`, depois da `</Signature>`:

```xml
<infNFeSupl>
  <qrCode><![CDATA[<qrUrl>]]></qrCode>
  <urlChave>https://www.homologacao.nfce.fazenda.sp.gov.br/NFCeConsultaPublica/Paginas/ConsultaNFCe.aspx</urlChave>
</infNFeSupl>
```

⚠️ **A ordem importa**: `infNFe → Signature → infNFeSupl`. A maioria dos
exemplos antigos põe `infNFeSupl` antes de Signature — isso é do leiaute
anterior e não vale para 4.00.

### 4. Envelopar em `<enviNFe>`

A SEFAZ NÃO recebe `<NFe>` solto. Ela espera um lote:

```xml
<enviNFe versao="4.00" xmlns="http://www.portalfiscal.inf.br/nfe">
  <idLote>1</idLote>
  <indSinc>1</indSinc>
  <NFe>... (com Signature e infNFeSupl) ...</NFe>
</enviNFe>
```

`indSinc=1` = envio síncrono (só permite 1 NFe por lote, que é o nosso caso).
`idLote` pode ser qualquer número de até 15 dígitos (ex: timestamp).

### 5. Envelope SOAP NFeAutorizacao4

```xml
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4">
      <enviNFe>...</enviNFe>
    </nfeDadosMsg>
  </soap:Body>
</soap:Envelope>
```

Endpoints SP NFC-e 4.00:
- Produção: `https://nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx`
- Homolog:  `https://homologacao.nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx`

Header HTTP: `Content-Type: application/soap+xml; charset=utf-8`

### 6. Resposta JSON ao chamador

A edge function espera receber:

```json
{
  "xml_assinado": "<NFe>... com Signature e infNFeSupl ...</NFe>",
  "xml_envelope": "<soap:Envelope>...</soap:Envelope>",
  "xml_retorno": "<resposta bruta da SEFAZ>",
  "cStat": "100",
  "nProt": "135...",
  "xMotivo": "Autorizado o uso da NF-e"
}
```

Extraia `cStat`, `nProt`, `xMotivo` do `<retEnviNFe>` (modo síncrono devolve
direto sem precisar consultar recibo).

## Checklist final antes de testar

- [ ] Signature inserida APÓS `</infNFe>` e ANTES de `<infNFeSupl>`
- [ ] QR Code com 4 parâmetros + hash SHA-1 hex maiúsculo do `param+CSC`
- [ ] `cIdToken` zero-padded para 6 dígitos
- [ ] Envelope `<enviNFe versao="4.00">` com `<idLote>` e `<indSinc>1</indSinc>`
- [ ] SOAP 1.2 (`application/soap+xml`)
- [ ] mTLS com PFX usando `https.Agent({ pfx, passphrase })`
- [ ] Reposta JSON com `xml_assinado`, `xml_envelope`, `xml_retorno`, `cStat`, `nProt`, `xMotivo`

