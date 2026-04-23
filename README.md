# SEFAZ Relay — Microserviço de transmissão NFC-e

Microserviço Node.js que recebe XML de NFC-e da edge function do Lovable, **assina digitalmente** com o certificado A1 e **transmite à SEFAZ-SP** usando mTLS (TLS mútuo, exigência da SEFAZ).

## Por que esse serviço existe?

A SEFAZ exige conexão **mTLS** (cliente apresenta certificado durante o handshake TLS). Edge functions (Deno/serverless) não suportam isso. Esse pequeno serviço Node.js resolve, porque o `https.Agent` do Node aceita certificado de cliente nativamente.

---

## Deploy gratuito no Render.com

### 1. Subir o código no GitHub

```bash
cd /caminho/onde/voce/baixou/sefaz-relay
git init
git add .
git commit -m "Initial commit: SEFAZ relay"
# crie um repo vazio em github.com (pode ser privado)
git remote add origin https://github.com/SEU_USUARIO/sefaz-relay.git
git branch -M main
git push -u origin main
```

### 2. Criar conta no Render (gratuito, sem cartão)

- Acesse https://render.com e crie conta com GitHub.

### 3. Criar Web Service

1. No painel do Render → **New +** → **Web Service**
2. Conecte o repositório `sefaz-relay` que você acabou de criar no GitHub
3. Preencha:
   - **Name**: `sefaz-relay` (ou outro nome — vai virar a URL)
   - **Region**: Oregon (US West) — irrelevante, SEFAZ é Brasil
   - **Branch**: `main`
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node index.js`
   - **Instance Type**: **Free**
4. Em **Environment Variables**, adicione:
   - `RELAY_TOKEN` → gere um token forte (ex: rode `openssl rand -hex 32` ou use https://www.uuidgenerator.net/ e concatene 2 UUIDs). **Guarde esse valor — você vai colar igual no Lovable.**
   - `NODE_ENV` → `production`
5. Clique em **Create Web Service**.

O deploy demora ~3 minutos na primeira vez.

### 4. Validar

Após o deploy, o Render mostra a URL pública (ex: `https://sefaz-relay-xxxx.onrender.com`).

Teste o health check no navegador:
```
https://sefaz-relay-xxxx.onrender.com/health
```
Deve retornar `{"status":"ok","uptime":...}`.

### 5. Voltar no Lovable

Me passe duas informações no chat:
1. A **URL pública** do Render (ex: `https://sefaz-relay-xxxx.onrender.com`)
2. O **RELAY_TOKEN** que você gerou (vou pedir via formulário seguro de secrets — não cole no chat aberto)

Eu adiciono os dois secrets (`SEFAZ_RELAY_URL` e `SEFAZ_RELAY_TOKEN`) e refatoro a edge function para usar o relay.

---

## Sobre o cold start (Render Free)

- Após **15 min sem requisições**, o Render derruba o serviço.
- Próxima requisição leva **30-50 segundos** para acordar (a edge function aguarda até 90s).
- Durante o expediente comercial, com vendas regulares, o serviço fica sempre acordado.
- Você pode ainda usar um serviço gratuito como [UptimeRobot](https://uptimerobot.com/) pingando `/health` a cada 5 minutos para manter o serviço sempre acordado (free tier permite até 50 monitores).

## Endpoints

### `GET /health`
Sem autenticação. Retorna `{ status: "ok", uptime: <segundos> }`.

### `POST /transmitir`
Header: `Authorization: Bearer <RELAY_TOKEN>`

Body JSON:
```json
{
  "xml": "<?xml...><NFe>...</NFe>",
  "pfx_base64": "MIIK...",
  "senha": "senha-do-certificado",
  "ambiente": "2",
  "chave": "35260400000000000000000000000000000000000000"
}
```

Resposta:
```json
{
  "sucesso": true,
  "xml_assinado": "<NFe>...<Signature>...</Signature></NFe>",
  "xml_retorno": "<retEnviNFe>...</retEnviNFe>",
  "cStat": "100",
  "xMotivo": "Autorizado o uso da NF-e",
  "nProt": "135260000000000",
  "tempo_ms": 1842
}
```

## Segurança

- O serviço **não armazena nada**: PFX e senha são usados em memória e descartados a cada request.
- Comunicação Lovable ↔ Render via HTTPS + token bearer.
- Certificado e senha trafegam apenas dentro do payload HTTPS (não vão para logs).
- Sem o `RELAY_TOKEN` correto, qualquer request é rejeitado com 401.
