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
    -subs | --recon-subs    (Opcional) : Procura por subdominios do dominio especificado. (amass)
    -u    | --Urls          (Opcional) : Busca Urls interligadas as URL's encontradas. (gau)
    -v    | --Verificar     (Opcional) : Verifica status das URL's encontradas. (httpx e remover repetidas)
    -e    | --Endpoints     (Opcional) : Procura por endspoints. (hawkraler)
    -p    | --Parametros    (Opcional) : Procura por parametros. (Paramspider)
    -s   | --Secrets        (Opcional) : Procura por keys e subdominios dentro das paginas nas URL's (SubDomainizer)
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
    mkdir -p $ResultsPath/$domain/Amass
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -P $ResultsPath/$domain/ > /dev/null 2>&1
    
    if [ -z "$ac" ]
    then
      amass enum -active -o $ResultsPath/$domain/$(date +%F)/domains_tmp.txt -d $domain -brute -w $ResultsPath/$domain/deepmagic.com-prefixes-top50000.txt -dir $ResultsPath/$domain/Amass > /dev/null 2>&1
    else
      amass enum -active -o $ResultsPath/$domain/$(date +%F)/domains_tmp.txt -d $domain -brute -w $ResultsPath/$domain/deepmagic.com-prefixes-top50000.txt -config $ac -dir $ResultsPath/$domain/Amass > /dev/null 2>&1
    fi

}

##  Gau

gau(){
echo -e ">> \e[36mGAU\e[0m is in progress"
gau $1 >> $ResultadoPath/$domain/$(date +%F)/$1/gau.txt
}

## Hawkraler

hawkraler(){
echo -e ">> \e[36mHakrwaler\e[0m is in progress"
echo -e $1 | hakrawler -forms -js -linkfinder -plain -robots -sitemap -usewayback -outdir $ResultadoPath/$domain/$(date +%F)/$1/hakrawler | kxss >> $ResultadoPath/$domain/$(date +%F)/$1/kxss.txt
}

## Paramspider e GF
paramspider(){
echo -e ">> \e[36mParamSpider\e[0m is in progress"
cd $FerramentasPath/ParamSpider/
python3 paramspider.py --domain $1 --exclude woff,css,js,png,svg,jpg -o paramspider.txt > /dev/null 2>&1

  if [ -s $FerramentasPath/ParamSpider/output/paramspider.txt ]
  then
    	mv ./output/paramspider.txt $ResultadoPath/$domain/$(date +%F)/$1/

      ## GF
      echo -e ">> \e[36mGF\e[0m is in progress"
      mkdir $ResultadoPath/$domain/$(date +%F)/$1/GF
      
      gf xss $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/xss.txt
      gf potential $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/potential.txt
      gf debug_logic $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/debug_logic.txt
      gf idor $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/idor.txt
      gf lfi $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/lfi.txt
      gf rce $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/rce.txt
      gf redirect $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/redirect.txt
      gf sqli $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/sqli.txt
      gf ssrf $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/ssrf.txt
      gf ssti $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt >> $ResultadoPath/$domain/$(date +%F)/$1/GF/ssti.txt
  fi
}

## Secrets e Dominios dentro do codigo fonte
secret(){
  echo -e ">> \e[36mSubDomainizer\e[0m is in progress"
  python3 $FerramentasPath/SubDomainizer/SubDomainizer.py -u $1 -o $ResultadoPath/$domain/$(date +%F)/$1/SubDomainizer.txt > /dev/null 2>&1
}
