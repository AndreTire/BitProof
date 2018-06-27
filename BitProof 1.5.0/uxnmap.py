import os


def get_nmap(options, ip):                               # nmap command for web site scanning
    command = "nmap " + options + " " + ip               # requiremend -> nmap tools for command os
    process = os.popen(command)
    results = str(process.read())
    return results

# print(get_nmap("-F", "216.58.205.110"))