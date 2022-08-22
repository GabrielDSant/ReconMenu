#!/bin/bash

##Variáveis.
ResultadoPath="$HOME/Auto-Recon/Resultado"
FerramentasPath="$HOME/Auto-Recon/Ferramentas"

##Funções

die() {
    printf '%s\n' "$1" >&2
    exit 1
}

help() {
    banner
    echo -e "Use : .recon.sh -d domain.tld -r -s
    -d    | --domain        (requer)   : Dominio em formato domain.tld.
    -subs | --recon-subs    (Opcional) : Procura por subdominios do dominio especificado. (amass)
    -u    | --Urls          (Opcional) : Busca Urls interligadas as URL's encontradas. (gau)
    -v    | --Verificar     (Opcional) : Verifica status das URL's encontradas. (httpx e remover repetidas)
    -e    | --Endpoints     (Opcional) : Procura por endspoints. (Linkfinder)
    -p    | --Parametros    (Opcional) : Procura por parametros. (Paramspider)
    -sS   | --Secret        (Opcional) : Procura por 'secrets' nas URL's (SecretFinder)
    -sP   | --ScanParametros(Opcional) : Procura por parametros com possiveis padrões de Vuln. (Gf & Gf-Pattern)
    -st   | --Scantemplates (Opcional) : Testa URL's atravês de templates. (nuclei)
    -sV   | --ScanVisual    (Opcional) : Faz um scan mais 'visual' dás urls. (aquatone)
    "
}