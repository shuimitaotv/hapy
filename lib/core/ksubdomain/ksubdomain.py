import os


def run_ksubdomain(domain):
    ksubdomains = []
    ksubdomain_folder = './lib/core'
    ksubdomain_file = '{}/{}.txt'.format(ksubdomain_folder, domain)

    os.system('chmod 777 ./lib/core/ksubdomain/ksubdomain_linux')
    os.system('./lib/core/ksubdomain/ksubdomain_linux -d {} -o {}'.format(domain, ksubdomain_file))
    try:
        with open(ksubdomain_file, 'rt') as f:
            for each_line in f.readlines():
                each_line_split = each_line.split('=>')
                subdomain = each_line_split[0].strip()                  # 子域名
                ksubdomains.append(subdomain)

        os.remove(ksubdomain_file)                         # 删除临时文件
    except Exception as e:
        ksubdomains = []

    return list(set(ksubdomains))