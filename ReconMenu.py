import os
import argparse

#iniciando argparser
parser = argparse.ArgumentParser()
args = parser.parse_args()

parser.add_argument("-d", "--Domain", help = "Dominio em formato domain.tld.", required=True)

parser.add_argument("-F", "--Full", help = "Roda tudo de recon que tem aqui amigão")

parser.add_argument("-subs", "--ReconSubs", help = "Procura por subdominios do dominio especificado. (amass)")
parser.add_argument("-u", "--Urls", help = "Busca Urls interligadas as URL's encontradas. (gau)")
parser.add_argument("-e", "--Endpoints", help = "Procura por endspoints. (linkfinder)")
parser.add_argument("-p", "--Parametros", help = "Procura por parametros. (Paramspider)")
parser.add_argument("-s", "--Secrets", help = "Procura por keys e subdominios dentro das paginas nas URL's (SubDomainizer)")


parser.add_argument("-v", "--Verificar", help = "Limpa as URL's com o httpx e retira duplicatas")


parser.add_argument("-sP", "--ScanParametros", help = "Procura por parametros com possiveis padrões de Vuln. (Gf & Gf-Pattern)")
parser.add_argument("-sT", "--ScanTemplates", help = "Testa URL's atravês de templates. (nuclei)")
parser.add_argument("-sV", "--ScanVisual", help = "Faz um scan mais 'visual' dás urls. (aquatone)")
parser.add_argument("-sC", "--ScanGit", help = "Procura por git exposeds. (goop)")



ResultadoPath='/root/Auto-Recon/Resultado'
FerramentasPath='/root/Auto-Recon/Ferramentas'

domain = args.Domain




banner = '''
    ____                         __  ___                      
   / __ \  ___   _____  ____    /  |/  /  ___    ____   __  __
  / /_/ / / _ \ / ___/ / __ \  / /|_/ /  / _ \  / __ \ / / / /
 / _, _/ /  __// /__  / /_/ / / /  / /  /  __/ / / / // /_/ / 
/_/ |_|  \___/ \___/  \____/ /_/  /_/   \___/ /_/ /_/ \__,_/                                                                                                                      
    '''

def start():
    print('Recon iniciando... Boa sorte Hunter!!')
    os.system(f'mkdir -p {ResultadoPath}/{domain}/')



## Recon Tools

def amassT():
    print('Iniciando Amass para enumeração de dominios...')
    os.system(f'mkdir -p {ResultadoPath}/{domain}/Amass')
    os.system(f'wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -P {ResultadoPath}/{domain}/Amass > /dev/null 2>&1')
    os.system(f'amass enum -active -o {ResultadoPath}/{domain}/domains_tmp.txt -d {domain} -brute -w {ResultadoPath}/{domain}/deepmagic.com-prefixes-top50000.txt -dir {ResultadoPath}/{domain}/Amass > /dev/null 2>&1')
    os.system(f'cat {ResultadoPath}/{domain}/domains_tmp.txt | sort -u > {ResultadoPath}/{domain}/amass.txt')

def gauT():
    os.system(f'gau >> {ResultadoPath}/{domain}/gau.txt')


def linkfinderT():
    os.system(f'python3 {FerramentasPath}linkfinder.py -i -d -o cli > {ResultadoPath}/{domain}/linkfinder.txt')

def paramspiderT():
    os.system(f'python3 {FerramentasPath}/paramspider.py --domain {domain} --exclude woff,css,js,png,svg,jpg -o {ResultadoPath}/{domain}/paramspider.txt > /dev/null 2>&1')
    arquivo = os.path.exists(f'{ResultadoPath}/{domain}/paramspider.txt')
    if arquivo is True:
        os.system(f'mv {FerramentasPath}/ParamSpider/output/paramspider.txt {ResultadoPath}/{domain}/')

def subdomainizerT():
    os.system(f'python3 {FerramentasPath}/SubDomainizer/SubDomainizer.py -u {domain} -o {ResultadoPath}/{domain}/SubDomainizer.txt > /dev/null 2>&1')


## Scan Tools ##

def GfT():
    os.system(f'mkdir -p $ResultadoPath/$domain/GF')

    os.system(f'gf xss {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/xss.txt')
    os.system(f'gf potential {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/potential.txt')
    os.system(f'gf debug_logic {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/debug_logic.txt')
    os.system(f'gf idor {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/idor.txt')
    os.system(f'gf lfi {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/lfi.txt')
    os.system(f'gf rce {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/rce.txt')
    os.system(f'gf redirect {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/redirect.txt')
    os.system(f'gf sqli {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/sqli.txt')
    os.system(f'gf ssrf {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/ssrf.txt')
    os.system(f'gf ssti {ResultadoPath}/{domain}/URLsLimpas.txt >> {ResultadoPath}/{domain}/GF/ssti.txt')

def nucleiT():
    os.system(f'nuclei -l {ResultadoPath}/{domain}/URLsLimpas.txt -t {FerramentasPath}/nuclei-templates/ -o {ResultadoPath}/{domain}/nuclei.txt > /dev/null 2>&1')

def aquatoneT():
    os.system(f'mkdir {ResultadoPath}/{domain}/Aquatone')
    os.system(f'cat {ResultadoPath}/{domain}/amass.txt | aquatone -chrome-path /snap/bin/chromium -ports xlarge > /dev/null 2>&1')

def goopT():
    os.system(f'goop -l {ResultadoPath}/{domain}/URLsLimpas.txt > {ResultadoPath}/{domain}/goop.txt')





##httpx

## Status-code httpx
# $ResultadoPath/$domain/$(date +%F)/$1/amass.txt
# $ResultadoPath/$domain/$(date +%F)/$1/gau.txt
# $ResultadoPath/$domain/$(date +%F)/$1/linkfinder.txt
# $ResultadoPath/$domain/$(date +%F)/$1/paramspider.txt
# $ResultadoPath/$domain/$(date +%F)/$1/SubDomainizer.txt

def httpxT():
    os.system (f'cat {ResultadoPath}/{domain}/SubDomainizer.txt {ResultadoPath}/{domain}/paramspider.txt {ResultadoPath}/{domain}/linkfinder.txt {ResultadoPath}/{domain}/gau.txt {ResultadoPath}/{domain}/amass.txt > {ResultadoPath}/{domain}/geral.txt')
    os.system (f'cat {ResultadoPath}/{domain}/geral.txt | httpx -silent | uniq -u > {ResultadoPath}/{domain}/URLsLimpas.txt')



#triggers

def full():
    print("Recon FULL em andamento, pega um café... ou uma cerveja :)")
    start()
    amassT()
    gauT()
    linkfinderT()
    paramspiderT()
    subdomainizerT()
    httpxT()
    
def main():
    print(banner)
    ##Recon
    if args.Full == True:
        full()
    if args.ReconSubs == True:
        amassT()
    if args.Urls == True:
        gauT()
    if args.Endpoints == True:
        linkfinderT()
    if args.Parametros == True:
        paramspiderT()
    if args.Secrets == True:
        subdomainizerT()

    ## Clear Urls
    if args.Verificar == True:
        httpxT()
    
    ## Scan
    if args.ScanParametros == True:
        GfT()
    if args.ScanTemplates == True:
        nucleiT()
    if args.ScanVisual == True:
        aquatoneT()
    if args.ScanGit == True:
        goopT()

if __name__ == '__main__':
    main()