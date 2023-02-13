from optparse import OptionParser
from lib.core.saveToExcel import saveToExcel
import os
import urllib3
import re 
import tld
import dns.resolver
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import openpyxl
from termcolor import cprint

def _init():
    global domain,output,overwrite,file

    usage = '\n\t' \
            'python3 %prog -d domain.com\n\t' \
            'python3 %prog --domainFile domain.txt\n\t'

    parse = OptionParser(usage=usage)
    parse.add_option('-d', '--domain', dest='domain', type='str', help='target domain')
    parse.add_option('-o', '--output', dest='output', type='str', default='./result', help='output file')            # 输出文件的位置
    parse.add_option('-f', '--file', dest='file', type='str', default=None, help='domain file')            # domain列表文件
    parse.add_option('-w', '--overwrite', dest='overwrite', type='int', default=0, help='overwrite an existing file with the same name')            # 覆盖同名文件

    options, args = parse.parse_args()
    domain,output,file,overwrite=options.domain,options.output,options.file,options.overwrite

    try:
        os.makedirs(output)
    except Exception:
        pass

    if domain:
        domain=get_main_domain(domain)
        expDomain(domain)

    if file:
        f=open(file)
        for line in f.readlines():
            domain=get_main_domain(line.strip('\n'))
            expDomain(domain)
        f.close()

    cprint(r'C段IP：{}', 'green')
    cprint(r'结束扫描'.format(), 'green')
    cprint(r'文件保存路径:{}'.format(output), 'green')
    
        
def expDomain(domain):

    excel = openpyxl.Workbook()
    excel.remove(excel[excel.sheetnames[0]])  # 删除第一个默认的表
    dmoainExcelSavePath='{}/{}.xlsx'.format(output, domain)
    
    # 判断域名是否已扫过
    if  os.path.exists(dmoainExcelSavePath) and not overwrite:
        cprint('[域名文件已存在] :{}'.format(domain), 'red')
        return 

    # 判断是否是泛解析
    isPanAnalysis = checkPanAnalysis(domain)
    
    if not isPanAnalysis :
        ksubdomains = callKsubdomain()
    else:
        ksubdomains = []
    
    print('[total: {}] ksubdomain: {}'.format(len(ksubdomains), ksubdomains))
    subdomains = printGetNewSubdomains([], ksubdomains)
    print('len [{}]'.format(len(subdomains)))

    # virustotal|ce.baidu.com|www.threatcrowd.org|url.fht.im|qianxun
    othersApiTotalSubdomains = othersApiSubdomain()
    print('[total: {}] webAPI: {}'.format(len(othersApiTotalSubdomains), othersApiTotalSubdomains))
    subdomains = printGetNewSubdomains(subdomains, othersApiTotalSubdomains)
    print('len [{}]'.format(len(subdomains)))

    # 爬虫(百度｜必应)
    spiderSubdomains = SpiderSubdomain()
    print('[total: {}] Spider: {}'.format(len(spiderSubdomains), spiderSubdomains))
    subdomains = printGetNewSubdomains(subdomains, spiderSubdomains)
    subdomains = printGetNewSubdomains(subdomains, [domain])

    # 保存子域名
    paramHtLinksSheet = saveToExcel(dmoainExcelSavePath, excel, '子域名')
    paramHtLinksSheet.save(subdomains,["子域名"])

    # 保存后台地址
    htSheet = saveToExcel(dmoainExcelSavePath, excel, '后台')
    htSheet.setTitle(["子域名","地址","标题"])
    allParamLinks={}
    for _domain in subdomains:
        paramLinks,htLinks= run_ParamLinks(_domain,htSheet)
        allParamLinks[_domain]=paramLinks

    #保存SQL注入
    sqlSheet = saveToExcel(dmoainExcelSavePath, excel, 'SQL注入')
    sqlSheet.setTitle(["子域名","漏洞类型","注入点","准确度"])
    for _domain in subdomains:
        if(len(allParamLinks[_domain])>0):
            run_SqlProbe(allParamLinks[_domain],sqlSheet) 
    
# 获取主域名
def get_main_domain(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    if url.startswith("http://www.") or url.startswith("https://www."):
        return ".".join(url.split(".")[1:])
    return ".".join(tld.get_tld(url, as_object=True).fld.split(".")[0:])

# 判断是否是泛解析
def checkPanAnalysis(domain):
    cprint('-' * 50 + 'check Pan-Analysis ...' + '-' * 50, 'green')
    panDomain = 'sadfsadnxzjlkcxjvlkasdfasdf.{}'.format(domain)
    try:
        dns_A_ips = [j for i in dns.resolver.query(panDomain, 'A').response.answer for j in i.items]
        print(dns_A_ips)
        cprint('[泛解析] {} -> {}'.format(panDomain, dns_A_ips), 'red')
        return True
    except Exception as e:
        cprint('[不是泛解析] :{}'.format(e.args), 'red')
        return False

# 调用kSubdomain脚本
def callKsubdomain():
    cprint('-' * 50 + 'Load ksubdomain ...' + '-' * 50, 'green')
    from lib.core.ksubdomain.ksubdomain import run_ksubdomain
    ksubdomains = run_ksubdomain(domain)
    return ksubdomains

# 打印脚本跑出了几个新的子域名，并返回最新最全的子域名列表  传递两个列表，old是前面收集好的子域名，new是刚跑完的脚本收集的子域名，进行比较.
def printGetNewSubdomains(old_subdomains, new_subdomains):
    if len(old_subdomains) > 0:
        newSubdomains = list(set(new_subdomains) - set(old_subdomains))
        print('[new :{}] {}'.format(len(newSubdomains), newSubdomains))
    return list(set(new_subdomains + old_subdomains))

# 获取域名的参数链接和后台链接（存活）
def run_ParamLinks(domain,sheet):
    cprint('-' * 50 + 'run_ParamLinks: ' + domain + '-' * 50, 'green')  # 启动网络空间引擎
    from lib.core.paramSpider.paramSpider import getParamLinks
    paramLinks,htLinks=getParamLinks(domain)
    for htLink in htLinks:
        htLink.insert(0,domain)
        sheet.add([htLink])
    return paramLinks,htLinks

# 获取域名的SQL注入点（存活）
def run_SqlProbe(links,sheet):
    cprint('-' * 50 + 'run_SqlProbe: ' + '-' * 50, 'green')
    from lib.exp.SQL.sqlProbe import detect 
    sqlProbe=detect(links)
    sql=[]
    _allsql=[]
    for _sqlLinks in sqlProbe:
        _sql=[]
        parsed_url = urllib3.util.parse_url(_sqlLinks[1])
        _sql.append(_sqlLinks[0])
        _sql.append(parsed_url.netloc + parsed_url.path)
        _sql.append(_sqlLinks[2])
        if _sql not in _allsql:
            _allsql.append(_sql)
            _sqlLinks.insert(0, parsed_url.netloc)
            sql.append(_sqlLinks)
    sheet.add(sql)

    return sqlProbe

# 调用virustotal|ce.baidu.com|www.threatcrowd.org|url.fht.im|的子域名收集脚本
def othersApiSubdomain():
    cprint('-' * 50 + 'Load VirusTotal threatcrowd url.fht.im ...' + '-' * 50, 'green')
    from lib.core.othersApiSubdomains.othersApiSubdomains import othersApiRun
    othersApiTotalSubdomains = othersApiRun(domain)   # 列表，存放子域名
    return othersApiTotalSubdomains

# 调用爬虫
def SpiderSubdomain():
    cprint('-' * 50 + 'Load Spider ...' + '-' * 50, 'green')  # 启动百度爬虫

    # 百度爬虫
    def BaiduSubdomain():
        cprint('Load BaiduSpider ...', 'green')  # 启动百度爬虫
        from lib.core.baiduSpider.baidu import BaiduSpider
        bdSubdomains,links = BaiduSpider().run_subdomain(domain)
        return bdSubdomains

    # 必应爬虫
    def BingSubdomain():
        cprint('Load BingSpider ...', 'green')  # 启动必应爬虫
        from lib.core.bingSpider.bing import BingSpider
        bingSubdomains,links = BingSpider().run_subdomain(domain)
        return bingSubdomains

    bdSubdomains = BaiduSubdomain()
    bingSubdomains = BingSubdomain()
    spiderSubdomains = list(set(bdSubdomains + bingSubdomains))
    return spiderSubdomains


if __name__ == '__main__':
    _init()
