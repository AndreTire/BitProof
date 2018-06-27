import os


def get_whois(url):                         #whois linux command
    command = "whois " + url
    process = os.popen(command)
    results = str(process.read())
    return results

# print(get_whois('185.25.204.67'))