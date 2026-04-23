# Relay SEFAZ-SP NFC-e v5 — com Validação XSD Oficial

## O que mudou em relação à v4

A grande mudança: **o relay agora valida o XML contra o XSD oficial da SEFAZ ANTES de transmitir**. Isso elimina o ciclo de "mandar e receber cStat 225 sem saber o motivo".

Quando o XML é inválido, o relay retorna **HTTP 422** com o elemento exato, linha e coluna do erro — em vez do genérico `cStat=225 Falha no Schema XML do lote de NFe` que a SEFAZ devolve.

## Setup no Render (ou em qualquer Node 18+)

### 1. Substitua os PEMs de CA Raiz no `index.js`

Procure por `COLE_AQUI_O_PEM_DA_AC_RAIZ_V2/V5/V10` e cole os PEMs reais que você já vinha usando na v4.

### 2. Baixe os schemas XSD oficiais

Crie a pasta `schemes/PL_009_V4/` e coloque dentro dela os arquivos abaixo (todos do repositório oficial `nfephp-org/sped-nfe`):

- `nfe_v4.00.xsd`
- `leiauteNFe_v4.00.xsd`
- `tiposBasico_v4.00.xsd`
- `xmldsig-core-schema_v1.01.xsd`
- `enviNFe_v4.00.xsd`

Comando rápido (Render terminal ou local):

```bash
mkdir -p schemes/PL_009_V4
cd schemes/PL_009_V4
BASE="https://raw.githubusercontent.com/nfephp-org/sped-nfe/master/schemes/PL_009_V4"
for f in nfe_v4.00.xsd leiauteNFe_v4.00.xsd tiposBasico_v4.00.xsd xmldsig-core-schema_v1.01.xsd enviNFe_v4.00.xsd; do
  curl -sLO "$BASE/$f"
done
```

### 3. Instalar dependências

```bash
npm install
```

A nova dependência é `libxmljs2`, que faz a validação XSD usando libxml2 nativo (mesmo motor que validadores oficiais usam).

### 4. Subir

```bash
npm start
```

Ou, no Render, basta dar push — o `Procfile`/start padrão já roda `node index.js`.

## Verificando que está tudo certo

```bash
curl https://SEU-RELAY.onrender.com/health
```

Deve responder algo como:

```json
{
  "ok": true,
  "ts": "2026-04-23T22:00:00.000Z",
  "schemas": { "nfe": true, "enviNFe": true }
}
```

Se aparecer `nfe: false`, é porque os XSDs não foram encontrados — confira a pasta `schemes/PL_009_V4/`.

## Como o erro vai aparecer no app a partir de agora

Antes:
```
NFC-e rejeitada: Falha no Schema XML do lote de NFe
```

Agora:
```
Schema XSD local (etapa nfe_v4.00):
  [L1:2345] Element 'ICMSSN500': Missing child element(s). Expected is one of (vBCSTRet, ...).
  [L1:2410] Element 'NFe': child element 'infNFeSupl' is invalid here.
```

Você pode abrir a venda rejeitada no app e ver o XML enviado + o diagnóstico — copiar e validar em ferramentas externas se quiser uma segunda opinião.

## Endpoint de depuração

Útil para validar um XML colado, sem precisar do PFX:

```bash
curl -X POST https://SEU-RELAY.onrender.com/validar \
  -H "Content-Type: application/json" \
  -d '{"xml": "<NFe>...</NFe>", "etapa": "nfe"}'
```

Resposta:
```json
{ "ok": false, "etapa": "nfe", "erros": [...] }
```
