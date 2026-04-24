# SEFAZ-SP NFC-e Relay v5.2

## O que mudou em relação à v5.1

A v5.0/v5.1 dependia do pacote **`libxmljs2`** para validar o XML contra o XSD oficial. Esse pacote precisa **compilar código nativo C++** (via `node-gyp`) na hora do `npm install`. No Render, o build está usando **Node 25**, que é incompatível com `libxmljs2` (e a fixação via `engines`/`.nvmrc` foi ignorada pelo provedor).

A v5.2 **resolve isso definitivamente** removendo o pacote nativo e usando o binário **`xmllint`** (parte do `libxml2`), que já vem instalado em todos os containers Linux do Render. Resultado:

- ✅ ZERO dependência nativa npm
- ✅ ZERO `node-gyp`
- ✅ Funciona em qualquer versão do Node (18, 20, 22, 25...)
- ✅ Mesma validação XSD oficial PL_009_V4
- ✅ Mesma resposta HTTP 422 + diagnóstico (linha, elemento, mensagem)

## Setup no Render

### 1. Substitua os arquivos

Faça upload de:
- `index.js`
- `package.json`

### 2. Cole seus PEMs

Em `index.js`, blocos `AC_RAIZ_V2`, `AC_RAIZ_V5`, `AC_RAIZ_V10` — substitua os placeholders pelos certificados reais que você já tinha na v4/v5.

### 3. Crie a pasta `schemes/PL_009_V4/`

Baixe os XSDs oficiais do repositório:
https://github.com/nfephp-org/sped-nfe/tree/master/schemes/PL_009_V4

Coloque todos os arquivos `.xsd` desse diretório na pasta `schemes/PL_009_V4/` do relay. Os essenciais:
- `nfe_v4.00.xsd`
- `enviNFe_v4.00.xsd`
- `leiauteNFe_v4.00.xsd`
- `tiposBasico_v4.00.xsd`
- `xmldsig-core-schema_v1.01.xsd`

### 4. Faça push e redeploy

O Render vai rodar `npm install` (sem `libxmljs2` agora) e iniciar normalmente. O `xmllint` já está disponível no PATH.

### 5. Verifique no log de boot

Você deve ver:
```
[XSD] xmllint disponível: true
[XSD] nfe_v4.00.xsd: true | enviNFe_v4.00.xsd: true
Relay SEFAZ-SP v5.2 (XSD via xmllint) rodando na porta XXXX
```

Se aparecer `xmllint disponível: false`, instale via Render shell: `apt-get install -y libxml2-utils` (mas isso é raro, vem instalado).

## Endpoints

- `GET /health` → status + flags de schemas
- `POST /transmitir` → fluxo completo (assina → valida XSD → transmite SEFAZ)
- `POST /validar` → valida um XML offline contra um schema (`{ xml, etapa: "nfe"|"envi" }`)

## Comportamento da rejeição XSD

Quando o XML falha no schema local, o relay responde **HTTP 422**:
```json
{
  "erro": "schema_local",
  "etapa": "nfe_v4.00",
  "xsd_erros": [
    { "linha": 47, "elemento": "ICMSSN500", "mensagem": "Element 'ICMSSN500': ..." }
  ],
  "xml_validado": "<NFe ...>"
}
```

O frontend (Vendas.tsx) já está preparado para ler esse formato e exibir o diagnóstico.
