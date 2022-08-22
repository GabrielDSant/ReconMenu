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
    --Recon--
    -subs | --recon-subs    (Opcional) : Procura por subdominios do dominio especificado. (amass) ok
    -u    | --Urls          (Opcional) : Busca Urls interligadas as URL's encontradas. (gau)ok
    -v    | --Verificar     (Opcional) : Verifica status das URL's encontradas. (httpx e remover repetidas) ok
    -e    | --Endpoints     (Opcional) : Procura por endspoints. (linkfinder) ok
    -p    | --Parametros    (Opcional) : Procura por parametros. (Paramspider) ok
    -s   | --Secrets        (Opcional) : Procura por keys e subdominios dentro das paginas nas URL's (SubDomainizer) ok
    --Scan--
    -sP   | --ScanParametros(Opcional) : Procura por parametros com possiveis padrões de Vuln. (Gf & Gf-Pattern)
    -sT   | --Scantemplates (Opcional) : Testa URL's atravês de templates. (nuclei)
    -sV   | --ScanVisual    (Opcional) : Faz um scan mais 'visual' dás urls. (aquatone)
    "
}

banner() {
    echo -e "
    ____                         __  ___                      
   / __ \  ___   _____  ____    /  |/  /  ___    ____   __  __
  / /_/ / / _ \ / ___/ / __ \  / /|_/ /  / _ \  / __ \ / / / /
 / _, _/ /  __// /__  / /_/ / / /  / /  /  __/ / / / // /_/ / 
/_/ |_|  \___/ \___/  \____/ /_/  /_/   \___/ /_/ /_/ \__,_/                                                                                                                      
    "
}

recon() {
    echo -e "Recon of \e[31m$1\e[0m is in progress"
    mkdir -p $ResultadoPath/$domain/$(date +%F)/$1
}

## RECON TOOLS 

amass(){
    echo -e ">> \e[36mAmass\e[0m is in progress"
    mkdir -p $ResultadoPath/$domain/Amass
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -P $ResultadoPath/$domain/Amass > /dev/null 2>&1
    
    if [ -z "$ac" ]
    then
      amass enum -active -o $ResultadoPath/$domain/$(date +%F)/domains_tmp.txt -d $domain -brute -w $ResultadoPath/$domain/deepmagic.com-prefixes-top50000.txt -dir $ResultadoPath/$domain/Amass > /dev/null 2>&1
    else
      amass enum -active -o $ResultadoPath/$domain/$(date +%F)/domains_tmp.txt -d $domain -brute -w $ResultadoPath/$domain/deepmagic.com-prefixes-top50000.txt -config $ac -dir $ResultadoPath/$domain/Amass > /dev/null 2>&1
    fi

}

##  Gau

gau(){
echo -e ">> \e[36mGAU\e[0m is in progress"
gau $1 >> $ResultadoPath/$domain/$(date +%F)/$1/gau.txt
}

## linkfinder

linkfinder(){
echo -e ">> \e[36mHakrwaler\e[0m is in progress"
cd $FerramentasPath/LinkFinder/
python3 linkfinder.py -i $1 -d -o cli > $ResultadoPath/$domain/$(date +%F)/$1/linkfinder.txt
}

## Paramspider
paramspider(){
echo -e ">> \e[36mParamSpider\e[0m is in progress"
cd $FerramentasPath/ParamSpider/
python3 paramspider.py --domain $1 --exclude woff,css,js,png,svg,jpg -o paramspider.txt > /dev/null 2>&1

  if [ -s $FerramentasPath/ParamSpider/output/paramspider.txt ]
  then
    	mv ./output/paramspider.txt $ResultadoPath/$domain/$(date +%F)/$1/
  fi
}

## Secrets e Dominios dentro do codigo fonte
secret(){
  echo -e ">> \e[36mSubDomainizer\e[0m is in progress"
  python3 $FerramentasPath/SubDomainizer/SubDomainizer.py -u $1 -o $ResultadoPath/$domain/$(date +%F)/$1/SubDomainizer.txt > /dev/null 2>&1
}


## SCAN ##

## GF

Gf(){
      echo -e ">> \e[36mGF\e[0m is in progress"
      mkdir $ResultadoPath/$domain/$(date +%F)/$1/GF
      
      gf xss $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/xss.txt
      gf potential $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/potential.txt
      gf debug_logic $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/debug_logic.txt
      gf idor $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/idor.txt
      gf lfi $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/lfi.txt
      gf rce $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/rce.txt
      gf redirect $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/redirect.txt
      gf sqli $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/sqli.txt
      gf ssrf $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/ssrf.txt
      gf ssti $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/ssti.txt
}


## Status-code httpx
# $ResultadoPath/$domain/$(date +%F)/$1/amass.txt
# $ResultadoPath/$domain/$(date +%F)/$1/gau.txt
# $ResultadoPath/$domain/$(date +%F)/$1/linkfinder.txt
# $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt
# $ResultadoPath/$domain/$(date +%F)/$1/SubDomainizer.txt

httpx(){
    cat $ResultadoPath/$domain/$(date +%F)/$1/SubDomainizer.txt $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt $ResultadoPath/$domain/$(date +%F)/$1/linkfinder.txt $ResultadoPath/$domain/$(date +%F)/$1/gau.txt $ResultadoPath/$domain/$(date +%F)/domains_tmp.txt > geral.txt
    cat geral.txt | httpx -silent | uniq -u > $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt