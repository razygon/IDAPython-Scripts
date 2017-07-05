import sys
import idaapi
import idautils
import idapython
import idc
from idaapi import Form
import pymongo
from pymongo import MongoClient
import subprocess

_IDAREADFUNMATRIX_GUID = 'd3babbb6-669b-4e2e-9a57-4df6ae89cf79'
_IDAREADFUNMATRIX_HOTKEY = 'shift-ctrl-f'

class MyError(Exception):
    def __init__(self, value):
        print value

class ConfirmTraceForm(Form):
    def __init__(self, msg):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Confirm Trace
====={note}===== 
""", {
            'note' : Form.StringLabel(msg)
        })
        
   
default_moduleName = idc.GetInputFile().replace('.','_')
default_dbpath = "D:\eclips\workspace\interestingFUN\win32\db"
moduleName = idc.AskStr(default_moduleName, 'The database name (default is the module name)')
dbpath = ''
dbpath = idc.AskStr(default_dbpath, 'The database path (default is FunctionMatrix path + projectname+db)')
if not os.path.exists(dbpath.replace('\\','/')):
    checkpath = ConfirmTraceForm('Database path does not exist, Please check')
    checkpath.Compile()
    checkath.Execute()
    raise MyError('Database path does not exist, Please check')           
dbexe = [r'C:\mongodb\bin\mongod.exe', '-port','24444', '-dbpath' ,dbpath]
dbprocess = subprocess.Popen(dbexe)
        
client = MongoClient('localhost',24444)
#what if connect failed?
db = client[moduleName]#projName
dbctrl = db[moduleName]
if 0 == dbctrl.count():
    check = ConfirmTraceForm('Target Database is empty, Please check')
    check.Compile()
    check.Execute()
    raise MyError('Target Database is empty, Please check')

func_name_ea = {name:ea for ea, name in idautils.Names()}
ftarget = 'alloc'
funlist = []
funfeaturelist = []
FIRST_RUN = 1
title = "Functions Searched"
cols = []
sample = dbctrl.find_one()
for col in sample:
    if col != '_id':
        if col == 'ea':
            col_item = [col,10]
        elif col == 'name':
            col_item = [col,19]
        else:
            col_item = [col,5]
        cols.append(col_item)

def DEBUG_PRINT(str):
#     print '[debug info]' 
#     print  str
    return



class IdxChoose2(idaapi.Choose2):
    '''
    Index Chooser Dialog
    '''
    def __init__(self, title, cols, items, deflt = 1):
        idaapi.Choose2.__init__(self, title, cols)
        self.items = items
        self.deflt = deflt 
    
    def OnClose(self):
        return

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        del self.items[n]
        return n

    def show(self):
        return self.Show(True)
    
def Get_FunctionFeatures():
    global ftarget, func_name_ea, dbctrl, FIRST_RUN, funlist, funfeaturelist, title, cols
    origin_ftarget = ftarget #pAllocateAndInitializeMDSURF
    ftarget = idc.AskStr(origin_ftarget, 'Type the Target String (CASE INSenstive)')
    if ftarget == '':
        print 'NO input'
        return
    if ftarget == origin_ftarget and not FIRST_RUN:
    # if target string doesn't change, then keep previous funlist, but first time run must be excluded
        DEBUG_PRINT("ftarget == origin_ftarget ")
        pass
    else:
        funlist = []        
        for f in func_name_ea.keys():
            if ftarget.lower() in f.lower():
#                 funlist.append((f,func_name_ea[f]))
                funlist.append(f)
        DEBUG_PRINT(funlist)
        funfeaturelist = []
        for fun in funlist:
            funfeature = dbctrl.find_one({"name":fun})
            if funfeature:
                featurelist = []
                for feature in funfeature:
                    if feature != '_id':
                        featurelist.append(funfeature[feature].strip('(,)').split(',')[0])
                DEBUG_PRINT(featurelist)
                funfeaturelist.append(featurelist) 
        DEBUG_PRINT(funfeaturelist)                
    if FIRST_RUN:
        FIRST_RUN = 0
#funfeaturelist prepared      
    DEBUG_PRINT("To show the window")
#     print title
#     print cols
    chooser = IdxChoose2(title, cols, funfeaturelist)  #, deflt = deflt_id
    id = chooser.show()
    if -1 == id:
        idc.Message('\n Index no change\n')
    else:
        ea = funfeaturelist[id][cols.index(['ea', 10])]
        print 'ea',ea
        type(ea)
        idaapi.jumpto(int(ea,16), -1,1)
        features = dbctrl.find_one({"ea":ea})
        for f in features:
            print '%-20s %s'%(f, features[f])
    DEBUG_PRINT("show finished")

idaapi.CompileLine('static Get_FunctionFeatures() { RunPythonStatement("Get_FunctionFeatures()"); }')
idc.AddHotkey(_IDAREADFUNMATRIX_HOTKEY, 'Get_FunctionFeatures')


