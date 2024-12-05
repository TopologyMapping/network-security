# Authentication_ZAP_GT_CRIVO

Este framework foi projetado para automatizar o processo de testes de segurança em aplicações web, utilizando autenticação para aumentar a superfície de ataque. Ele permite que o usuário teste diversas aplicações sem a necessidade de interagir diretamente com o conteúdo da aplicação. O framework automatiza o processo de captura de metadados, extração de elementos-chave e autenticação nas aplicações. Após a autenticação, o framework processa os metadados e cria um arquivo de contexto que pode ser utilizado posteriormente em testes de segurança.

## ZAP

O Zed Attack Proxy (ZAP) é uma ferramenta utilizada para testes de segurança em aplicações web. O framework usa uma imagem Docker do ZAP, que inclui um proxy e uma API que roda na porta `8080`. A ideia central é conectar o framework ao proxy do ZAP no momento em que uma aplicação web é instanciada. Dessa forma, o ZAP analisa a aplicação utilizando varreduras passivas e ativas durante os testes de penetração.

O framework interage com o ZAP enviando comandos e recebendo dados por meio da API. Os dados necessários para criar o arquivo de contexto da aplicação são extraídos dos alertas gerados pelo ZAP, que indicam possíveis vulnerabilidades. Esses alertas são configurados para que, ao serem acionados, necessitem de evidências, que podem ser fornecidas pelo usuário ou pelos desenvolvedores da ferramenta. Nesta versão, estamos utilizando os alertas definidos pelos próprios desenvolvedores do ZAP.

## Framework

O framework conecta-se à API do ZAP para realizar testes e capturar metadados. Inicialmente, ele verifica a existência de arquivos de configuração no diretório reservado no volume. Assim que identificados, o fluxo de execução começa. Cada arquivo de configuração é analisado e seus campos são interpretados utilizando a biblioteca Pydantic. Se um arquivo não contiver as informações essenciais definidas na classe de configuração, ele será desconsiderado.

### Exemplo de classe de configuração:

```python
class User(BaseModel):
    context: str
    url: List[str]
    url_login: Optional[str] = None
    exclude_urls: List[str] = []
    report_title: Optional[str] = "Report"
    login: str
    password: str
```

Apenas dois atributos são opcionais: a URL da página de login e o título do relatório. Se a URL de login não for fornecida, o framework utiliza o spider do ZAP para tentar identificar as URLs da aplicação a partir da URL base. No entanto, nem sempre é possível encontrar a página de login automaticamente, por isso é recomendável fornecer essa URL sempre que possível. Se o spider falhar em encontrar a URL de login, um erro será lançado.

O framework utiliza o proxy do ZAP para acessar as aplicações web. Ele faz isso configurando o navegador Firefox com certificados de segurança e o proxy, permitindo que o ZAP capture os metadados das requisições durante a autenticação. O Selenium é utilizado para interagir com as aplicações web de duas formas:

### 1. Captura dos elementos de autenticação

O Selenium instancia o navegador na página de login e lista todos os elementos da página. Em seguida, ele filtra apenas os elementos do formulário de login. Se a página não retornar nenhum elemento do formulário, como ocorre em algumas aplicações que utilizam técnicas para ocultar esses dados na DOM, o framework pode não ser capaz de capturá-los.

Quando possível, o framework identifica os campos de login e senha utilizando expressões regulares (regex). As regex são configuradas para ignorar maiúsculas, minúsculas, pontuações e símbolos, cobrindo assim uma maior variedade de elementos. Se o framework não conseguir encontrar os campos necessários, o usuário pode adicionar regex personalizadas no arquivo `framework/keywords/regex_words/valid_elements.txt`.

### 2. Realização do login na aplicação web

Após identificar os elementos de login, o Selenium envia as credenciais pelo proxy do ZAP. O framework então verifica se o login foi bem-sucedido observando se o formulário ainda está presente e se o ZAP detecta a autenticação através do alerta `Authentication Request Identified`.

Com a autenticação realizada, o framework captura os metadados relevantes para criar o contexto da aplicação, incluindo o corpo da requisição (request body) do POST de autenticação e o tipo de gerenciamento de sessão da aplicação. Esses dados são usados para gerar um arquivo YAML com o plano de automação da aplicação, que será utilizado para instanciar a aplicação e finalizar o processo de criação do contexto.

## Web Server

O servidor web foi projetado para criar uma interface entre o framework e o usuário. Ele roda na porta `8000` e expõe o volume no localhost, permitindo que o usuário visualize os arquivos gerados.

## Docker Compose

O `docker-compose` foi configurado para permitir que as três aplicações interajam entre si. Uma sub-rede em modo *bridge* foi criada e as dependências entre os containers foram definidas para garantir a ordem correta de execução. Primeiro, o container do ZAP é iniciado, seguido pelo container do framework, e por último o container do servidor web.

## Arquivo de Configuração

O arquivo de configuração deve estar em formato JSON. Abaixo está um exemplo de como organizá-lo:

```json
{
    "context": "Test_DVWA",
    "url": ["http://192.168.15.95/dvwa/"],
    "url_login": "http://192.168.15.95/dvwa/login.php",
    "report_title": "Report_dvwa",
    "login": "admin",
    "password": "admin"
}
```

O Pydantic fará o *parser* do arquivo e extrairá os atributos necessários para a criação do contexto. Um exemplo será disponibilizado na raiz do repositório, chamado `example.json`.

## Makefile

O `Makefile` realiza operações importantes para o funcionamento correto do framework:

1. Gera a chave da API que será utilizada pelo ZAP, definindo-a como uma variável de ambiente. A cada execução, a chave é gerada aleatoriamente.
2. Executa o script `copy.sh`, que copia os arquivos de configuração do diretório especificado para o volume do arcabouço.

### copy.sh

Este script recebe como parâmetro o diretório dos arquivos de configuração e copia-os para o volume, evitando duplicações a cada execução. Apenas arquivos `.json` são copiados, e se algum arquivo não passar no *parser* do Pydantic, ele será ignorado.

## Entrada (Input)

Antes de iniciar o framework, é necessário criar um arquivo de configuração da aplicação a ser testada, como mostrado acima. Após criar um ou mais arquivos de configuração, armazene-os em um único diretório, cujo caminho será utilizado como parâmetro do `Makefile`.

## Saída (Output)

O framework gera um arquivo com o plano dos *scans* passivos e o contexto da aplicação.

## Como Usar

Para iniciar o framework, utilize o comando:

```bash
make run DIR="diretório dos arquivos"
```

O `docker-compose` irá subir três containers: o ZAP, o framework e o servidor web. Os containers rodam em *background*. Para visualizar os logs, use os comandos:

```bash
docker logs -f authentication_zap_gt_crivo-zaproxy-1
docker logs -f authentication_zap_gt_crivo-framework-1
```

Após os testes, os resultados serão armazenados no volume do *compose* e poderão ser acessados pelo servidor web na URL `localhost:8000`.

Para finalizar a aplicação, use:

```bash
docker compose down
```
