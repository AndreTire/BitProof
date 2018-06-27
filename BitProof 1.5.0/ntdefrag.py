# defragger
import sys
import subprocess


def mainDefrag():
    if sys.maxsize > 2 ** 32:
        run_cmd = 'defrag /C'  # 64-bit python/cmd
    else:
        run_cmd = r'%systemroot%\sysnative\defrag /C'  # 32-bit python/cmd

    output, err = subprocess.Popen(run_cmd, stdout=subprocess.PIPE, shell=True).communicate()  # Pipe error
    # print(output)
    if err:
        s = 'process fail, error {}'.format(err)
    else:
        s = 'process sucess'
    return s, output, err