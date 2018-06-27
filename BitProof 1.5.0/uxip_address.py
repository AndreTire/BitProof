import os                                           # library for manipulate os command


def get_ip_address(url):                            # url domain dns resolving method
    command = "host " + url
    process = os.popen(command)
    results = str(process.read())
    marker = results.find('has address') + 12       # cleaning the string
    return results[marker:].splitlines(0)


# print(get_ip_address('google.com'))

