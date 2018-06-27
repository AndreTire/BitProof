import os


def create_dir(directory):                          #directory log
    if not os.path.exists(directory):               #if not exits an old scan, create a new one
        os.makedirs(directory)

def write_file(path, data):                         #create file log
    f = open(path, 'a')
    f.write(data)
    f.close()