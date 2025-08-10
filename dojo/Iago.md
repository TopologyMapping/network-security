# Tutorial: Utilizando a Branch com Atualizações Extras

Este guia explica como manter sua branch sempre atualizada com o **master oficial** do [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) e incluir as funcionalidades extras da branch [`rnp-project`](https://github.com/LeoOMaia/django-DefectDojo/tree/rnp-project), incluindo o plugin de votos para Findings.

## Passos para Atualizar sua Branch com os Extras

### Clonar o Repositório Oficial e Configurar o Remoto

Se ainda não clonou o repositório oficial, faça isso agora:

```bash
# Clonar o repositório oficial
git clone https://github.com/DefectDojo/django-DefectDojo.git
cd django-DefectDojo
```

Agora, adicione o repositório que contém os extras:

```bash
# Adicionar o repositório com os extras como um remoto
git remote add leo https://github.com/LeoOMaia/django-DefectDojo.git
```

### Manter o Master Atualizado

Para garantir que sua branch esteja sempre baseada na versão mais recente do **master oficial**:

```bash
# Ir para a branch master
git checkout master

# Atualizar com a versão mais recente do repositório oficial
git pull origin master
```

### Incluir os Extras da Branch `rnp-project`

Agora, aplique as mudanças da branch `rnp-project` em cima do master atualizado:

```bash
# Criar uma nova branch baseada no master atualizado
git checkout -b minha-branch-atualizada

# Fazer merge da branch rnp-project
git merge leo/rnp-project
```

Se não houver conflitos, o merge será feito automaticamente. Caso contrário, resolva os conflitos manualmente antes de continuar.

## Configurações Adicionais do Plugin de Votos

O plugin de votos requer algumas configurações extras no DefectDojo, que serão aplicadas automaticamente ao adicionar o repositório com os extras como um remoto:

### 1. Modificações nos Dockerfiles

O `Dockerfile` dos contêineres Django foi atualizado para:

- Criar a pasta `/app/polls_db` dentro do contêiner.
- Executar um script Python que gera o banco SQLite3 dos votos.
- Ajustar permissões para permitir escrita/leitura.

Trecho adicionado ao `Dockerfile`:

```dockerfile
RUN \
    mkdir -p /app/polls_db && \
    python3 /app/dojo/polls_plugin/create_votes_table.py && \
    chmod -R 775 /app/polls_db && \
    chown -R ${appuser}:${appuser} /app/polls_db
```

### 2. Atualização do `docker-compose.yml`

O `docker-compose.yml` foi modificado para montar um volume para persistência do banco de votos:

```yaml
services:
  uwsgi:
    volumes:
      - "defectdojo_sqlite:/app/polls_db"

volumes:
  defectdojo_sqlite: {}
```

### 3. Configurações no `local_settings.py`

Adicionadas URLs para manipulação dos votos:

```python
from django.conf.urls import include
from django.urls import re_path

PRELOAD_URL_PATTERNS = [
    re_path(r"^finding/", include("dojo.polls_plugin.urls")),
    re_path(r"^finding/open/", include("dojo.polls_plugin.urls")),
]
```

### 4. Estrutura do Plugin

O plugin está localizado em `/dojo/polls_plugin/` e contém:

```plaintext
django-DefectDojo/
├── dojo/
│   ├── polls_plugin/
│   │   ├── __init__.py
│   │   ├── create_votes_table.py
│   │   ├── urls.py
│   │   ├── views.py
```

### 5. Arquivos  do Plugin

Os arquivos dentro de `/app/polls_db/` incluem:

```python
# create_votes_table.py
import os
import sqlite3

import environ

root = environ.Path(__file__) - 3
DB_DIR = root("polls_db")
DB_PATH_FINDING_POLLS = os.path.join(DB_DIR, "finding_polls.db")

os.makedirs(DB_DIR, exist_ok=True)

with sqlite3.connect(DB_PATH_FINDING_POLLS) as connection:
    cursor = connection.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS votes (
        user_id INTEGER NOT NULL,
        finding_id INTEGER NOT NULL,
        vote TEXT CHECK(vote IN ('Mild', 'Moderate', 'Severe', 'Critical')) NOT NULL,
        UNIQUE(user_id, finding_id)
    );
    """
    
    cursor.execute(create_table_query)
    connection.commit()
```

```python
# urls.py
from django.urls import re_path
from .views import get_votes, submit_vote

urlpatterns = [
    re_path(r"^get_votes/$", get_votes, name="get_votes"),
    re_path(r"^submit_vote/$", submit_vote, name="submit_vote"),
]
```

```python
# views.py
from django.http import JsonResponse
import sqlite3
from django.contrib.auth.decorators import login_required

import logging

logger = logging.getLogger(__name__)

DB_PATH = "/app/polls_db/finding_polls.db"

@login_required
def get_votes(request):
    user_id = request.user.id
    finding_ids = request.GET.get("finding_ids", "").split(",")

    if not finding_ids:
        return JsonResponse({"error": "Missing finding_ids"}, status=400)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT finding_id, vote 
                FROM votes 
                WHERE user_id=? AND finding_id IN ({})
            """.format(
                    ",".join(["?"] * len(finding_ids))
                ),
                (user_id, *finding_ids),
            )
            rows = cursor.fetchall()

        votes = {str(row[0]): row[1] for row in rows}

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse(votes)


@login_required
def submit_vote(request):
    if request.method != "POST":
        logger.error("Invalid request method")
        return JsonResponse({"error": "Invalid request method"}, status=405)

    user_id = request.user.id
    finding_id = request.POST.get("finding_id")
    vote = request.POST.get("vote")

    if not (finding_id and vote):
        logger.error("Missing data: finding_id=%s, vote=%s", finding_id, vote)
        return JsonResponse({"error": "Invalid data"}, status=400)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO votes (user_id, finding_id, vote)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id, finding_id) 
                DO UPDATE SET vote=excluded.vote
            """,
                (user_id, finding_id, vote),
            )
            conn.commit()

    except Exception as e:
        logger.exception("Error occurred while saving vote: %s", str(e))
        return JsonResponse({"error": str(e)}, status=500)

    logger.info(
        "Vote saved successfully: user_id=%d, finding_id=%d, vote=%s",
        user_id,
        finding_id,
        vote,
    )
    return JsonResponse({"message": "Vote saved successfully"})

```



### 6. Adição de Dropdowns nos Findings

O arquivo `findings_list_snippet.html` foi modificado para incluir a coluna `Vote`, com dropdowns para seleção da severidade.

```html
<th>{% trans "Vote" %}</th>
<td>
    <select class="vote-dropdown" data-finding-id="{{ finding.id }}" style="display: none;">
        <option value=""></option>
        <option value="Mild">Mild</option>
        <option value="Moderate">Moderate</option>
        <option value="Severe">Severe</option>
        <option value="Critical">Critical</option>
    </select>
</td>
```

### 6. Scripts para Processamento de Votos

Foram adicionados scripts JavaScript para:

- Buscar votos ao carregar a página.
- Salvar votos ao selecionar uma opção no dropdown.

```html
<script type="application/javascript">
window.addEventListener('load', function() {
    const voteDropdowns = document.querySelectorAll(".vote-dropdown");
    const findingIds = Array.from(voteDropdowns).map(dropdown => dropdown.dataset.findingId);

    fetch(`/finding/get_votes/?finding_ids=${findingIds.join(',')}`)
        .then(response => response.json())
        .then(data => {
            voteDropdowns.forEach(dropdown => {
                const findingId = dropdown.dataset.findingId;
                if (data.hasOwnProperty(findingId)) {
                    dropdown.value = data[findingId];
                }
            });
        });
});

document.addEventListener('change', function(event) {
    if (event.target.classList.contains("vote-dropdown")) {
        const findingId = event.target.dataset.findingId;
        const vote = event.target.value;

        fetch("/finding/submit_vote/", {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value,
            },
            body: `finding_id=${findingId}&vote=${vote}`
        })
        .catch(() => location.reload());
    }
});
</script>
```

## Construir e Subir o DefectDojo

Após atualizar a branch e configurar os ajustes acima, rode os seguintes comandos para reconstruir e subir a aplicação:

```bash
docker compose -f docker-compose.yml build
docker compose -f docker-compose.yml up -d
```