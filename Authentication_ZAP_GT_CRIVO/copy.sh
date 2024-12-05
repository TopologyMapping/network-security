#!/bin/bash

# Verifica se foi passado somente 1 argumento
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <diretorio_origem>"
    exit 1
fi

# Argumento do diretório que será copiado
ORIGEM=$1

DIR_DESTINO="input_config" 
# volume no compose 
DESTINO="/shared_data/$DIR_DESTINO"


# Verifica se o diretório de origem existe
if [ ! -d "$ORIGEM" ]; then
    exit 1
fi

# Verifica se o diretório de destino existe se não existir, criar
docker compose exec framework bash -c "mkdir -p $DESTINO && rm -rf $DESTINO/*"

# comando que apaga todos os arquivos de configuração se houver antes de copiar os novos.

# Copia apenas o conteúdo .json do diretório de origem para o volume
for file in "$ORIGEM"/*.json; do
    if [ -f "$file" ]; then
        docker compose cp "$file" framework:"$DESTINO/$(basename "$file")"
    fi
done


echo "Conteúdo copiado de $ORIGEM para $DESTINO com sucesso."
