# ===============================================================================
# StartFM.py here is used to load idbs and FunctionMatrix.py and also get configuration to decide which model to run   
# 
# Output:
# The results are stored in Mongo db, in the form of one idb one file. 
# 
# Created by razygon 2013/09/11
# last update: 2013/09/23 
# ===============================================================================


import os
import sys
import subprocess


def cmd_fmt():
    logger.info('''invalid parameter
            StartFM.py project_name target_folder/target_idb \n
            target_folder: is a folder which contains idbs.
            For more info refer to ReadMe
            '''
    )
    
import logging
def get_logger(name, level=logging.DEBUG):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    ch = logging.StreamHandler()
    #ch.setFormatter(logging.Formatter('[%(asctime)s] - %(name)s line %(lineno)d - %(levelname)s: %(message)s'))
    ch.setFormatter(logging.Formatter('[%(levelname)s] %(message)s [%(name)s line %(lineno)d]'))
    logger.addHandler(ch)

    return logger

logger = get_logger('StartFM Log')
    
if __name__ == '__main__':

    argc = len(sys.argv)
    flag_no_idb = False
    __idblist = []
    proj_name = ''
    current_path = os.getcwd()
    script_folder = current_path
    script = current_path + r'\FunctionMatrix.py'
    if 1 == argc: #for debug
        proj_name = r'user32'
        __idblist = [r'D:\Win7Kernel\win7_32Libs_vm\user32.idb']
    elif 3 <= argc : #walk exe dir path
        proj_name = sys.argv[1]
        target = sys.argv[2]
        print target
        if os.path.isfile(target):
            root,ext = os.path.splitext(target)
            if '.idb' == ext:
                __idblist = [target]
            elif 'idbs.txt' == target:
                with open(target,'r') as fr:
                    for line in fr:
                        if '.idb' in line:
                            __idblist.append(line)
            else:
                cmd_fmt()
                sys.exit(0)
        elif os.path.isdir(target):
            for (roots, dirs, files) in os.walk(target):
#                 file_path = os.path.join(roots,dirs)
                for file in files:
                    filepath = os.path.join(roots,file)
                    root,ext = os.path.splitext(filepath)
                    if '.idb' == ext:
                        __idblist.append(filepath)
                    
#         ==========
#         for model argument 
#         ========== 



    else:
        cmd_fmt()
        sys.exit(0)
        
    try:
        #open MongoDB
        dbpath = proj_name + r'\db'
        if not os.path.exists(dbpath.replace('\\','/')):
            os.makedirs(dbpath.replace('\\','/'))            
        dbexe = [r'C:\mongodb\bin\mongod.exe', '-port','24444', '-dbpath' ,dbpath]
        dbprocess = subprocess.Popen(dbexe)
    except:
        print 'open database sever failed, check whether path is right %s'%dbpath
        raise

    for idb in __idblist:
        logger.info('apply {script} on {idb}'.format(script = os.path.basename(os.path.dirname(script)), idb = idb))
        args = r'\"{arg}\"'.format(arg=(script_folder,proj_name))
        cmd = r'idaq -S" \"{script}\" {args}" "{idb}"'.format(script = script, args = args, idb = idb)
        print 'cmd' + cmd
        ret = subprocess.call(cmd)


        if ret:#fail
            print 'fail'
#             self._log_fail('apply script fail: idb={idb}, script = {script}'.format(idb = idb, script = script))
        else:
            print 'finished'

dbprocess.send_signal(0) # 0 IS CTRL-C SIGNAL
#     dbprocess.kill()
# start mongo server