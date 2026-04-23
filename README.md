# SEFAZ Relay — NFC-e SP

Microserviço Node.js que recebe XML não assinado da Edge Function (Lovable Cloud / Supabase),
assina com certificado A1 (PFX) via XMLDSig e transmite à SEFAZ-SP por mTLS.

## Deploy no Render.com

1. Suba este diretório para um repositório GitHub.
2. Render.com → **New → Web Service** → conecte o repo → plano **Free**.
3. Build Command: `npm install` *(o postinstall baixa automaticamente as cadeias raiz da ICP-Brasil)*
4. Start Command: `npm start`
5. Em **Environment**, adicione:
   - `RELAY_TOKEN` = (mesmo valor do secret `SEFAZ_RELAY_TOKEN` no Lovable)
6. Após deploy, acesse `https://<seu-app>.onrender.com/health` e confira o JSON:
   ```json
   { "status": "ok", "trustedCAs": 149, "icpBrasilCAs": 3 }
   ```
   Se `icpBrasilCAs` aparecer como `0`, rode manualmente no shell do Render:
   `node scripts/download-cas.js` e faça redeploy.

## Endpoints

- `GET /health` — status público
- `POST /transmitir` — protegido por `Authorization: Bearer <RELAY_TOKEN>`
  ```json
  {
    "xml": "<NFe>...</NFe>",
    "pfx_base64": "...",
    "senha": "...",
    "ambiente": "2",
    "chave": "35261112345678000199650010000000019100000018"
  }
  ```

## Trust store (resolução do erro `unable to get local issuer certificate`)

O servidor combina:
- **CAs padrão da Mozilla** embutidas no Node (`tls.rootCertificates`, ~146 CAs).
- **AC Raiz ICP-Brasil v2, v5 e v10**, baixadas em build-time via `scripts/download-cas.js` de
  `acraiz.icpbrasil.gov.br`.

Isso permite validar a cadeia do servidor SEFAZ sem desabilitar `rejectUnauthorized`.

## Atualizar cadeias manualmente

```bash
node scripts/download-cas.js
```

Recomendado revisitar a cada 12 meses ou quando a SEFAZ trocar de AC.

## Segurança

- Stateless: o PFX nunca é gravado em disco; usado em memória e descartado.
- Token bearer obrigatório em `/transmitir`.
- TLS 1.2+ obrigatório no envio à SEFAZ.
