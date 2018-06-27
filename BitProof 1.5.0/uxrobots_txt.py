from urllib import *


def get_robots_txt(url):                                  # request for file not index for google or other search engine
    if url.endswith('/'):
        path = url
    else:
        path = url + '/'

    robot = urlopen(path + "robots.txt")
    data = str(robot.read())
    return data

# print(get_robots_txt('https://www.reddit.com/'))
