import os                                           #library for manipulate os command


def get_ip_address(url):                            #url domain dns resolving method
    command = "nslookup " + url
    process = os.popen(command)
    results = str(process.read())
    data = results.split(' ')                       #cleaning the string
    results = data[len(data) - 1]
    data = results.split('\n')
    results = data[0]
    return results


#print(get_ip_address('google.com'))

