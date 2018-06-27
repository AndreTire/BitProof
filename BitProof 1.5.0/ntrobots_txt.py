from urllib import *


def get_robots_txt(url):                                                    # request for file not index for google or other search engine
    try:
        if url.endswith('/'):
            path = url
        else:
            path = url + '/'

        robot = urlopen(path + "robots.txt")
        data = str(robot.read())
        return data
    except:
        return "This site don't provide the file robot.txt \n " \
               "Can be a error on link or a shadow link/shadow DNS/phishing link; Be carefull on open it!"


# print(get_robots_txt('https://www.reddit.com/'))


