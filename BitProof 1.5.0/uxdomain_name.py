from tld import get_tld                         # library for tdl packet


def get_domain_name(url):                       # top level domain analysis
    domain_name = get_tld(url)
    return domain_name


# print(get_domain_name('https://google.com/'))

