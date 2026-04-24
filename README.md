# SEFAZ-SP NFC-e Relay v5.3

## O que mudou (v5.2 → v5.3)

### Diagnóstico baseado em log real do banco

Capturamos o XML exato que o relay v5.2 estava enviando. O envelope tem esta estrutura:

```xml
<enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">
  <idLote>1</idLote>
  <indSinc>1</indSinc>
  <NFe xmlns="http://www.portalfiscal.inf.br/nfe">   ← xmlns REDUNDANTE
    <infNFe ...>
    ...
```

O `xmllint` (validador local) **aceita** namespace redundante porque é tecnicamente válido em XML. **A SEFAZ-SP NÃO aceita** — o parser dela retorna `cStat=225 — Falha no Schema XML do lote de NFe` mesmo o XSD oficial passando.

### Por que o `<NFe>` vem com `xmlns` próprio?

A assinatura digital (`xml-crypto`) usa canonicalização exclusiva (`xml-c14n-20010315`). Para a assinatura ser válida quando a NFe é destacada do envelope para validação isolada, o `<NFe>` **precisa** ter seu próprio `xmlns` no momento da assinatura. Se removermos antes de assinar, a assinatura quebra.

### Correção

Em `buildEnviNFe()`:
1. Remove o prólogo `<?xml ... ?>`.
2. Remove **somente** o atributo `xmlns="http://www.portalfiscal.inf.br/nfe"` da tag raiz `<NFe>` (regex ancorada em `^<NFe ...>`).
3. Conteúdo interno (`infNFe`, `infNFeSupl`, `Signature`) fica **intacto**.
4. A assinatura continua válida porque foi computada sobre o XML original e referencia `<infNFe>` via `local-name()`.

Resultado: `<enviNFe ...><idLote>1</idLote><indSinc>1</indSinc><NFe><infNFe...>...</NFe></enviNFe>` — sem namespace duplicado.

---

## Deploy no Render

1. Substitua `index.js` no repositório.
2. **Não precisa** mudar `package.json` (mesmo da v5.2).
3. Restaure os PEMs reais (AC_RAIZ_V2, V5, V10) no topo do arquivo.
4. Garanta que `schemes/PL_009_V4/` existe com os XSDs.
5. Push → Render redeploy automático.

## Como confirmar que funcionou

Após o deploy, emita uma NFC-e e verifique:

- **Cenário sucesso**: cStat=100 ("Autorizado o uso da NF-e") + protocolo retornado.
- **Cenário ainda falha 225**: significa que há outro problema. Olhe o log do relay no Render — agora o XML transmitido NÃO terá mais o `xmlns` duplicado, e a investigação parte de outro ponto (provavelmente CSC mal configurado, encoding, ou conteúdo de algum campo).

## Verificação rápida do XML após a correção

Procure no log do relay (Render dashboard) ou no `logs_sefaz.request` por:

```
<enviNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00"><idLote>1</idLote><indSinc>1</indSinc><NFe><infNFe...
```

Se aparecer `<NFe>` sem atributos = correção aplicada com sucesso.
Se ainda aparecer `<NFe xmlns="...">` = a regex não casou (caso muito raro de espaços extras); abrir issue.

