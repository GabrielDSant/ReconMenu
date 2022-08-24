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

    -FullRecon              (Opcional) : Roda tudo de recon que tem aqui amigão

    -sD   | --recon-subs    (Opcional) : Procura por subdominios do dominio especificado. (amass) ok
    -u    | --Urls          (Opcional) : Busca Urls interligadas as URL's encontradas. (gau)ok
    -e    | --Endpoints     (Opcional) : Procura por endspoints. (linkfinder) ok
    -p    | --Parametros    (Opcional) : Procura por parametros. (Paramspider) ok
    -s    | --Secrets       (Opcional) : Procura por keys e subdominios dentro das paginas nas URL's (SubDomainizer) ok

    --Limpar arquivos de repetições e status code != 200--
     -v    | --Verificar    (Opcional) : Verifica status das URL's encontradas. (httpx e remover repetidas) ok

    --Scan--

    -FullScan

    -sP   | --ScanParametros(Opcional) : Procura por parametros com possiveis padrões de Vuln. (Gf & Gf-Pattern)
    -sT   | --Scantemplates (Opcional) : Testa URL's atravês de templates. (nuclei)
    -sV   | --ScanVisual    (Opcional) : Faz um scan mais 'visual' dás urls. (aquatone)
    -sC   | --ScanGit       (Opcional) : Procura por git exposeds. (goop)
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

start() {
    echo -e "Recon of \e[31m$1\e[0m is in progress"
    mkdir -p $ResultadoPath/$domain/$(date +%F)/$1
}

## RECON TOOLS 

amassT(){
    echo -e ">> \e[36mAmass\e[0m is in progress"
    mkdir -p $ResultadoPath/$domain/Amass
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -P $ResultadoPath/$domain/Amass > /dev/null 2>&1
          
    amass enum -active -o $ResultadoPath/$domain/$(date +%F)/domains_tmp.txt -d $domain -brute -w $ResultadoPath/$domain/deepmagic.com-prefixes-top50000.txt -dir $ResultadoPath/$domain/Amass > /dev/null 2>&1
    cat $ResultadoPath/$domain/$(date +%F)/domains_tmp.txt | sort -u > $ResultadoPath/$domain/$(date +%F)/$1/amass.txt
}

##  Gau

gauT(){
echo -e ">> \e[36mGAU\e[0m is in progress"
gau $1 >> $ResultadoPath/$domain/$(date +%F)/$1/gau.txt
}

## linkfinder

linkfinderT(){
echo -e ">> \e[36mHakrwaler\e[0m is in progress"
cd $FerramentasPath/LinkFinder/
python3 linkfinder.py -i $1 -d -o cli > $ResultadoPath/$domain/$(date +%F)/$1/linkfinder.txt
}

## Paramspider
paramspiderT(){
echo -e ">> \e[36mParamSpider\e[0m is in progress"
cd $FerramentasPath/ParamSpider/
python3 paramspider.py --domain $1 --exclude woff,css,js,png,svg,jpg -o paramspider.txt > /dev/null 2>&1

  if [ -s $FerramentasPath/ParamSpider/output/paramspider.txt ]
  then
    	mv ./output/paramspider.txt $ResultadoPath/$domain/$(date +%F)/$1/
  fi
}

## Secrets e Dominios dentro do codigo fonte
subdomainizerT(){
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

nucleiT(){
    echo -e ">> \e[36mNuclei\e[0m is in progress"
    nuclei -l $ResultadoPath/$domain/$(date +%F)/URLsLimpas.txt -t $FerramentasPath/nuclei-templates/ -o $ResultsPath/$domain/$(date +%F)/$1/nuclei.txt > /dev/null 2>&1

}

aquatoneT(){
    echo -e ">> \e[36mAquatone\e[0m is in progress"
    mkdir $ResultsPath/$domain/$(date +%F)/Aquatone
    cd $ResultsPath/$domain/$(date +%F)/Aquatone
    cat $ResultadoPath/$domain/$(date +%F)/$1/amass.txt | aquatone -chrome-path /snap/bin/chromium -ports xlarge > /dev/null 2>&1

}

goopT(){
    echo -e ">> \e[36mGoop\e[0m is in progress"
    ##cat $ResultadoPath/$domain/$(date +%F)/$1/URLsLimpas.txt | xargs -I@ sh -c 'goop -f @' > GitTest.txt
    goop -l $ResultadoPath/$domain/$(date +%F)/$1/URLsLimpas.txt > $ResultadoPath/$domain/$(date +%F)/$1/goop.txt
}

##httpx

## Status-code httpx
# $ResultadoPath/$domain/$(date +%F)/$1/amass.txt
# $ResultadoPath/$domain/$(date +%F)/$1/gau.txt
# $ResultadoPath/$domain/$(date +%F)/$1/linkfinder.txt
# $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt
# $ResultadoPath/$domain/$(date +%F)/$1/SubDomainizer.txt

httpxT(){
    echo -e ">> \e[36mHttpx\e[0m is in progress"
    cat $ResultadoPath/$domain/$(date +%F)/$1/SubDomainizer.txt $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt $ResultadoPath/$domain/$(date +%F)/$1/linkfinder.txt $ResultadoPath/$domain/$(date +%F)/$1/gau.txt $ResultadoPath/$domain/$(date +%F)/$1/amass.txt > $ResultadoPath/$domain/$(date +%F)/$1/geral.txt
    cat $ResultadoPath/$domain/$(date +%F)/$1/geral.txt | httpx -silent | uniq -u > $ResultadoPath/$domain/$(date +%F)/$1/URLsLimpas.txt
}


## Main ##

main(){
    if [-v full] ## Vai scanear se a opção for true.
    then
        echo -e "Recon FULL em andamento, pega um café... ou uma cerveja :)"
        start
        amassT
        gauT
        linkfinderT
        paramspiderT
        subdomainizerT
        httpxT
    fi

    if [-v subs]
    then
        amassT
    fi

    if [-v urls]
    then
        gauT
    fi

    if [-v endpoint]
    then
        linkfinderT
    fi

    if [-v parametros]
    then
        paramspiderT
    fi

    if [-v secrets]
    then
        subdomainizerT
    fi

    ## Scan

    if [-v ScanParametros]
    then
        GfT
    fi

    if [-v ScanTemplates]
    then
        nucleiT
    fi

    if [-v ScanVisual]
    then
        aquatoneT
    fi

    if [-v verificar]
    then
        httpxT
    fi

    if [-v ScanGit]
    then
        goopT
    fi
}

    while :; do
        case $1 in
            -h|--help)
                help
                exit
                ;;
            -d|--domain)
                if ["$2"];then
                    domain=$2
                    shift
                else
                    die 'Erro: "--domain" não pode ficar vázio.'
                fi
                ;;
            ##recon tools
            -FullRecon)
                full = true
                shift
                ;;
            -sD)
                subs = true
                shift
                ;;
            -u)
                urls = true
                shift
                ;;
            -e)
                endpoint = true
                shift
                ;;
            -p)
                parametros = true
                shift
                ;;
            -s)
                secrets = true
                shift
                ;;
            ## Scans tolls
            -sP)
                ScanParametros = true
                shift
                ;;
            -sT)
                ScanTemplates = true
                shift
                ;;
            -sV)
                ScanVisual = true
                shift
                ;;
            -sG)
                ScanGit = true
                shift
                ;;
            ## Verificar txts
            -v)
                verificar = true
                shift
                ;;
            *)
                break
        esac
        
        shift
done
            
                
            
## Fazer os ifs -etc das outras opções agradeço Gabriel Lucas