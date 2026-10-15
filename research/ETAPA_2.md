# Etapa 2: compilacao aberta e mapeamento offline

Status: **ferramentas de pesquisa funcionando; XboxInput completo NAO compilado
nem portado para 16537; nenhum arquivo aprovado para instalar no Xbox**.

O usuario nao possui o XDK original. O XDK e software para PC, nao hardware.
Nao foi obtido um instalador licenciado e nao se deve confundir o GDK dos
consoles atuais, XNA ou XDKbuild do xeBuild com o toolset necessario.

## Ferramentas efetivamente instaladas/utilizadas

Instalacao portatil em pasta de trabalho, sem mudar PATH global, registro,
servicos, firewall, seguranca do Windows ou requerer reinicializacao:

- Zig 0.14.1, download oficial:
  https://ziglang.org/download/0.14.1/zig-x86_64-windows-0.14.1.zip
  SHA-256 conferido com o indice oficial:
  `554F5378228923FFD558EAC35E21AF020C73789D87AFEABF4BFD16F2E6FEED2C`.
- Ambiente Python isolado, com Capstone 5.0.9, pefile 2024.8.26 e PyCryptodome
  4.0.0. Os scripts XEX desta etapa nao usam criptografia, CPUKey ou keyvault.
- xsdk de https://github.com/xenosworks/xsdk, commit
  `0e8af8fb434a45ddf2ce4a2b858082d68b411aca`: usados o linker script e elf2xex
  como referencia externa. Nao instalado seu GCC modificado nem seu runtime.
- idaxex de https://github.com/emoose/idaxex, commit
  `f388a502cbe84efd25e36d38f20d1a99cb2f166e`: usada sua copia libmspack
  (LGPL-2.1) para compilar uma DLL de analise local com nosso adaptador.
  `build_lzx_bridge.ps1` reproduz esse build. Preservar licencas dos projetos.
- O xex1tool precompilado 0.44 foi baixado da release do autor, hash conferido
  com o digest do GitHub `BE374C3C18A34C4B8820AF2EF7E764FF6109FA2ACBF9A0794C644A26F4A36BBB`.
  Falhou ao iniciar neste host, exit -1073740791. Nao foi usado para extrair
  imagens; a DLL compilada do fonte e o extrator proprio resolveram essa etapa.
- Foram inspecionados flash-dump-tool e Xbox-360-Crypto como referencias para
  trabalho futuro no kernel. Nao foram executados para alterar imagens e nao
  forneceram um kernel 16537 extraido nesta etapa. O primeiro tem extracao/
  patching de CE ainda incompletos e nao resolve a cadeia split-CB por si so.

Nao foi instalado Visual Studio, XDK proprietario, WSL ou qualquer programa no
Xbox. Nao houve alteracao de backups, launch.ini, USB ou NAND/eMMC.

## O que realmente compila

1. Suite nativa C++ upstream, com Zig: **11 alvos passaram**, incluindo parser,
   fila/transporte, rumble, DPC simulado e politicas de UI.
2. Suite de vetores PowerShell: **20 vetores GIP**, Guide, rumble e invariantes
   de mapeamento passaram.
3. Verificacoes estaticas upstream: **3 scripts passaram**.
4. Testes Python de inventario, extracao e mapeamento: **17 testes passaram**.
5. `build_open_smoke.ps1`: o parser C++ real upstream e uma entrada minima
   foram compilados para PowerPC big-endian, linkados em ELF32 e empacotados
   em um XEX2 de titulo, usando ferramentas abertas.

O ultimo build tem 135.168 bytes e SHA-256
`289C7F78ABC191678BF11CBF4E82BA96C671BB42173A79CABB40A5648F2C83ED`.
E apenas uma fixture de compilacao: recebe bytes sinteticos, nao le USB,
nao importa kernel/XAM e NAO e um plugin DashLaunch ou diagnostico de console.
**Nao copiar para o Xbox.** Empacotar um XEX nao prova que o loader ou o
hardware o executam corretamente.

Comandos reproduziveis a partir da raiz do fork (substituir caminhos):

```powershell
./tests/run_native_tests.ps1 -CompilerPath CAMINHO_ZIG_EXE
./tests/run_parser_tests.ps1
./research/build_open_smoke.ps1 -ZigPath CAMINHO_ZIG_EXE `
  -PythonPath CAMINHO_PYTHON_EXE -XsdkRoot CAMINHO_XSDK `
  -OutputDirectory NOVA_PASTA_DE_BUILD
python -m unittest discover -s research -p 'test_*.py' -v
```

O driver Zig 0.14.1 falhou com access violation em tentativas de compilar e
linkar os dois fontes PowerPC C++ num comando so. Separar a compilacao dos
objetos e o link resolveu o build. Nao foi atribuido a causa a otimizacao;
tentativas tanto O2 como O0 falharam no fluxo combinado. A fixture usa O0.

### O que ainda NAO compila

O MSBuild .NET tentou o projeto original e falhou com MSB4019, falta de
`Microsoft.Cpp.Default.props`. Alem disso, faltam toolset Xbox, headers XTL,
CRT/Win32 Xbox e a etapa de imagem do XDK. Instalar apenas MSBuild ou VS moderno
nao soluciona isso. RXDK360 tambem exige o XDK licenciado do usuario.

A alternativa aberta nao e drop-in: precisamos adaptar as interfaces XTL,
runtime e a ABI do kernel. O target generico PowerPC usado na fixture **nao
implementa a convencao Xbox para chamadas a exports**, em especial registros
64-bit, stack e argumentos. Nao chamar exports usando esse build sem resolver
a ABI. O xsdk usa um GCC modificado com convencao propria para esse fim.

## XAM: resultados offline reais

`extract_xex.py` extrai somente XEX2 NAO criptografado, validando SHA-1 da
cadeia de blocos antes da descompactacao. Recusa saida ja existente ou igual
ao arquivo de entrada. Nao le chaves. Nao valida assinatura Microsoft.

| Imagem | Blocos compactados verificados | PE extraido | SHA-256 do PE |
| --- | --- | --- | --- |
| XAM 16537 preservado do console | 41 | 6.356.992 bytes | EA93892A0260260085001261BF28316AB8CC749EF3F47DFF32687109B77C785E |
| XAM 17559 xl_hdd do kit local | 43 | 6.356.992 bytes | 79775EC12F081D6FE4E1C87A637A7863C146A7E3A1959C4272511B8A7784C9AA |

O 17559 de comparacao e uma variante xl_hdd, nao se presume identico a uma
imagem stock ou ao que foi efetivamente executado no console.

Ambos tem base preferencial 0x815F0000 e tabela de exports XEX valida,
base ordinal 1 e 2.890 entradas. Os oito exports consultados existem em
secoes executaveis. Isso confirma entradas offline, NAO ABI/comportamento.

| Ordinal XAM / uso upstream | Endereco 16537 | Endereco 17559 de comparacao |
| --- | --- | --- |
| 400 / XamInputGetCapabilities | 0x816F2330 | 0x816F2E70 |
| 401 / XamInputGetState | 0x816F09C8 | 0x816F14E8 |
| 402 / XamInputSetState | 0x816F0C20 | 0x816F1740 |
| 447 / classificador Xbox original, opcional | 0x816E0340 | 0x816E0DE8 |
| 463 / titulo atual, opcional | 0x816DF910 | 0x816E03B8 |
| 685 / XamInputGetCapabilitiesEx | 0x816F0798 | 0x816F12B8 |
| 746 / UI pelo Guide | 0x816C7280 | 0x816C7DE8 |
| 1183 / notificacoes opcionais | 0x816A2620 | 0x816A3128 |

`map_xam.py` valida magic/base/bounds e reporta correspondencias sem escolher
uma silenciosamente. Seu resultado e sempre marcado como candidato offline.

### Callback privado: evidencia mais forte que uma busca simples

A assinatura upstream de 12 bytes tem exatamente uma correspondencia alinhada
em secao executavel em cada PE:

- 17559: **0x816D9060**, coincide com o endereco usado pelo driver original.
- 16537: **0x816D8610**, candidato correspondente para o port.

Desassemblagem PowerPC dos dois trechos mostrou um wrapper de 11 instrucoes,
mesmas operacoes de registradores e teste de parametro, terminando em dois
desvios de cauda. Destinos:

| Caminho | 16537 | 17559 |
| --- | --- | --- |
| Ramo nao zero do teste | 0x816D8500 | 0x816D8F50 |
| Ramo zero do teste | 0x816D8240 | 0x816D8CD8 |

Isso aumenta a confianca na correspondencia, mas **nao certifica os callees,
estruturas, ownership, efeitos ou assinatura completa**. Nenhum desses
enderecos foi incorporado ao driver para execucao.

## Proximo trabalho necessario

1. Obter/extrair o kernel 16537 para analise offline de USB, exports e layouts,
   sem presumir que CE base seja o kernel final apos as patches de boot.
2. Escolher e implementar a cadeia aberta para chamadas com a ABI Xbox e para
   um modulo sysdll. A fixture atual e um titulo sem imports, nao esse modulo.
3. Validar callbacks e exports em profundidade e criar perfil por build.
   Manter 16537 recusado pelo driver enquanto o perfil estiver incompleto.
4. Primeiro teste futuro: diagnostico separado e delimitado, sem hooks/patches,
   com plano para sair/recuperar o boot. Somente depois habilitar USB e input.

Os dumps, PE extraidos, CPUKey e DLLs/EXEs baixados continuam fora do Git.
Os fontes do driver upstream permanecem inalterados. Nao houve conexao ao
console nesta etapa. Nao ha garantia de sucesso nem prazo de conclusao.
