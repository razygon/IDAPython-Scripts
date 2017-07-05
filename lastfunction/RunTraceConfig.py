import sqlite3
import subprocess
import distutils.spawn

class FuncListChoose2(Choose2):
    def __init__(self, title, cols, items, embedded):
        if(embedded):
            Choose2.__init__(self, title, cols, embedded=True)
        else:
            Choose2.__init__(self, title, cols)
        self.items = items
    
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
  
class TraceConfigForm(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Trace Config
<#Provide the PIN's main executable path#PIN's EXE    :{iPinExe}>
<#Provide the output dir where the generated files reside#Output Dir   :{iOutputDir}>
<#Provide the target process's main executable path#Process's EXE:{iTargetExe}>
""", {
            'iPinExe' : Form.FileInput(swidth=60, open=True),
            'iOutputDir' : Form.DirInput(swidth=60),
            'iTargetExe' : Form.FileInput(swidth=60, open=True),
        })

class TraceModeForm(Form):
    def __init__(self, attachMode):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Trace Mode
{iFormChangeCb}
<Attach Mode:{pin_attach}>{iAttachMode}>
<#Provide the target process's pid#Process's PID:{iTargetPid}>
Trace Mode
<Function Count:{func_count}>
<Multi Function Global:{multi_func_global}>
<Multi Function Target (need function count):{multi_func_target}>
<Last Function (need function count):{last_func}>
<Single Function (need function count):{single_func}>{iTraceMode}>
""", {
            'iAttachMode' : Form.ChkGroupControl(('pin_attach',)),
            'iTargetPid' : Form.NumericInput(tp=Form.FT_DEC),
            'iTraceMode': Form.RadGroupControl(('func_count', 'multi_func_global', 'multi_func_target', 'last_func', 'single_func')),
            'iFormChangeCb': Form.FormChangeCb(self.OnFormChange)
        })
        self.enableAttachMode = attachMode
        
    def EnableAttachMode(self, enable):
        self.EnableField(self.iTargetPid, enable)
        self.enableAttachMode = enable
        
    def OnFormChange(self, fid):
        if fid == -1: # initialise
            self.EnableAttachMode(self.enableAttachMode)
            self.EnableField(self.multi_func_target, False)
        elif fid == self.pin_attach.id:
            self.EnableAttachMode(not self.enableAttachMode)
        return 1
        
class SingleFuncTraceForm(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Single Function Trace
{iFormChangeCb}
Function Entry:  {iFuncAddr} 
Function Count:  {iFuncCount}
<#Provide the count to start tracing#Start Trace Count:{iStartTraceCount}>
<Step Into Callee:{step_into_callee}>
<Enable End Tracing:{end_trace}>{iChkGroup}>
<#Provide the execution count to end tracing#End Trace Count  :{iEndTraceCount}>
""", {
            'iFuncAddr' : Form.NumericLabel(0, Form.FT_HEX),
            'iFuncCount' : Form.NumericLabel(0, Form.FT_DEC),
            'iStartTraceCount' : Form.NumericInput(tp=Form.FT_DEC),
            'iChkGroup': Form.ChkGroupControl(('step_into_callee', 'end_trace')),
            'iEndTraceCount' : Form.NumericInput(tp=Form.FT_DEC),
            'iFormChangeCb': Form.FormChangeCb(self.OnFormChange)
        })
    
    def EnableEndTraceOption(self, enable):
        self.EnableField(self.iEndTraceCount, enable)
        self.enableEndTrace = enable
    
    def OnFormChange(self, fid):
        if fid == -1: # initialise
            self.EnableEndTraceOption(False) # disable the end trace option by default  
        elif fid == self.end_trace.id: # the check box is checked
            self.EnableEndTraceOption(not self.enableEndTrace)
        return 1

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
        
class LastFuncTraceForm(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Last Function Trace
{iFormChangeCb}
Function Entry:  {iFuncAddr} 
Function Count:  {iFuncCount}
<#Provide the count to start tracing#Start Trace Count:{iStartTraceCount}>
<Enable End Tracing:{end_trace}>{iChkGroup}>
<#Provide the execution count to end tracing#End Trace Count  :{iEndTraceCount}>
""", {
            'iFuncAddr' : Form.NumericLabel(0, Form.FT_HEX),
            'iFuncCount' : Form.NumericLabel(0, Form.FT_DEC),
            'iStartTraceCount' : Form.NumericInput(tp=Form.FT_DEC),
            'iChkGroup': Form.ChkGroupControl(('end_trace',)),
            'iEndTraceCount' : Form.NumericInput(tp=Form.FT_DEC),
            'iFormChangeCb': Form.FormChangeCb(self.OnFormChange)
        })
    
    def EnableEndTraceOption(self, enable):
        self.EnableField(self.iEndTraceCount, enable)
        self.enableEndTrace = enable
    
    def OnFormChange(self, fid):
        if fid == -1: # initialise
            self.EnableEndTraceOption(False) # disable the end trace option by default
        elif fid == self.end_trace.id: # the check box is checked
            self.EnableEndTraceOption(not self.enableEndTrace)
        return 1
        
class MultiFuncGlobalTraceForm(Form):
    def __init__(self, chooser):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Single Function Trace
<Function List:{iFuncListChooser}>
<Step Into Callee:{step_into_callee}>{iChkGroup}>
""", {
            'iChkGroup': Form.ChkGroupControl(('step_into_callee', )),
            'iFuncListChooser' : Form.EmbeddedChooserControl(chooser)
        })

class ShowCommsForm(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Trace DB Selector
<#Provide the trace DB's file#Trace DB:{iTraceDBFile}>
""", {
            'iTraceDBFile' : Form.FileInput(swidth=60, open=True)
        })
    
class ShowCmdsForm(Form):
    def __init__(self, configObject):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Select Command
{iFormChangeCb}
======================
    <ShowComms    :{iShowCommsBtn}> 
    <ListFuncCount:{iListFuncCountBtn}>
    <AddFunc      :{iAddFuncBtn}>
    <ShowFuncList :{iShowFuncListBtn}>
    <TraceConfig  :{iTraceConfigBtn}>
    <StartTrace   :{iStartTraceBtn}>
    <StopTrace    :{iStopTraceBtn}>
======================
""", {
            'iShowCommsBtn' : Form.ButtonInput(self.OnShowCommsBtn),
            'iListFuncCountBtn' : Form.ButtonInput(self.OnListFuncCountBtn),
            'iAddFuncBtn' : Form.ButtonInput(self.OnAddFuncBtn),
            'iShowFuncListBtn' : Form.ButtonInput(self.OnShowFuncListBtn),
            'iTraceConfigBtn' : Form.ButtonInput(self.OnTraceConfigBtn),
            'iStartTraceBtn' : Form.ButtonInput(self.OnStartTraceBtn),
            'iStopTraceBtn' : Form.ButtonInput(self.OnStopTraceBtn),
            'iFormChangeCb': Form.FormChangeCb(self.OnFormChange)
        })
        self.configObject = configObject
        
    def OnShowCommsBtn(self, code=0):
        self.configObject.showComms()
    
    def OnListFuncCountBtn(self, code=0):
        self.configObject.listFuncCount()
    
    def OnAddFuncBtn(self, code=0):
        self.configObject.addFunc()
        
    def OnShowFuncListBtn(self, code=0):
        self.configObject.showFuncList()
        
    def OnTraceConfigBtn(self, code=0):
        self.configObject.callConfig()
        
    def OnStartTraceBtn(self, code=0):
        self.configObject.callTrace()
        
    def OnStopTraceBtn(self, code=0):
        self.configObject.stopTrace() 
        
    def OnFormChange(self, fid):
        _idaapi.formchgcbfa_close(self.p_fa, fid, 0)
    
class RunTraceParser:
    def __init__(self):
        self.iConfigSet = False
        self.iPinPath = distutils.spawn.find_executable('pin.exe') # search for pin.exe from PATH
        if not self.iPinPath:
            self.iPinPath = '*.exe'
        self.iTargetPath = '*.exe'
        self.iWorkDir = os.path.dirname(os.path.realpath(__file__)) # this file's dir
        self.iOutputDir = os.path.dirname(self.iWorkDir) + '\\runtrace_output'
        if(not os.path.exists(self.iOutputDir)):
            os.makedirs(self.iOutputDir)
        self.iTraceMode = 0
        self.iPinToolPath = self.iWorkDir+'\\context_logger.dll'
        self.iAttachMode = False
        self.iTargetPid = 0
        
        inputFileName = GetInputFile()
        extIdx = inputFileName.rfind('.')
        self.iModuleName = inputFileName[0:extIdx]
        self.iModuleExt = inputFileName[extIdx+1:]
        
        self.funcList = []
        self.funcListCols = [['Function Address', 15], ['Function Name', 15]]
        self.funcListName = 'Funtions to Trace'
        
        self.cmdsInterface = ShowCmdsForm(self)
        self.cmdsInterface.Compile()
    
    def _CreateFuncRangeDB(self):
        db_file = self.iOutputDir + '\\' + self.iModuleName + '_' + self.iModuleExt + '_funcRange.db'
        if(os.path.exists(db_file)):
            return
        
        sqliteConn = sqlite3.connect(db_file)
        sqliteCur = sqliteConn.cursor()
        
        sqliteCur.execute('CREATE TABLE FuncRange (start_rva INTEGER, end_rva INTEGER)')
        ida_func_list = idautils.Functions()
        
        img_base = idaapi.get_imagebase()
        
        for func_ea in ida_func_list:
            pfn = idaapi.get_func(func_ea)
            sqliteCur.execute('INSERT INTO FuncRange VALUES (?, ?)', (pfn.startEA-img_base, pfn.endEA-1-img_base))
        
        sqliteConn.commit()
        sqliteCur.close()
        sqliteConn.close()
    
    def _GetFuncCountFromDB(self, funcEntry):
        db_file = self.iOutputDir + '\\' + self.iModuleName + '_' + self.iModuleExt + '_funcCount.db'
        if(not os.path.exists(db_file)):
            print '[Warning]No funcCount.db found, plese click TraceConfig to check Output Dir or run function count tracing to generate a new funcCount.db'
            return -1
        sqliteConn = sqlite3.connect(db_file)
        sqliteCur = sqliteConn.cursor()
        funcEntryRva = funcEntry - idaapi.get_imagebase()
        for row in sqliteCur.execute('SELECT count FROM FuncCount WHERE func_rva=?', (funcEntryRva, )):
            sqliteCur.close()
            sqliteConn.close()
            return row[0]
        sqliteCur.close()
        sqliteConn.close()
        print '[Warning]The selected function cannot be found in funcCount.db, please choose other functoins to do tracing.'
        return 0
    
    def _TraceFuncCount(self):
        self._CreateFuncRangeDB()
        cmd = ''
        if(self.iAttachMode):
            cmd = r'"{pin}" -logfile "{pinLogFile}" -pid {pid} -t "{pintool}" -logfile "{pintoolLogFile}" -m {mod_name} -o "{output_dir}" -t 0'.format(pin=self.iPinPath, pinLogFile=self.iOutputDir+'\\pin.log', pid=self.iTargetPid, pintool=self.iPinToolPath, pintoolLogFile=self.iOutputDir+'\\'+self.traceFileSignature+'.log', mod_name=GetInputFile(), output_dir=self.iOutputDir)
        else:
            cmd = r'"{pin}" -logfile "{pinLogFile}" -t "{pintool}" -logfile "{pintoolLogFile}" -m {mod_name} -o "{output_dir}" -t 0 -- "{exe_path}"'.format(pin=self.iPinPath, pinLogFile=self.iOutputDir+'\\pin.log', pintool=self.iPinToolPath, pintoolLogFile=self.iOutputDir+'\\'+self.traceFileSignature+'.log', mod_name=GetInputFile(), output_dir=self.iOutputDir, exe_path=self.iTargetPath)
        subprocess.Popen(cmd)
    
    def _TraceLastFunc(self):
        #cmd prolog
        cmd = ''
        if(self.iAttachMode):
            cmd = r'"{pin}" -logfile "{pinLogFile}" -pid {pid} -t "{pintool}" -logfile "{pintoolLogFile}" -m {mod_name} -o "{output_dir}" -t 3 -s {funcEntry} -sc {startTraceCount} -fs {traceFileSignature}'.format(pin=self.iPinPath, pinLogFile=self.iOutputDir+'\\pin.log', pid=self.iTargetPid, pintool=self.iPinToolPath, pintoolLogFile=self.iOutputDir+'\\'+self.traceFileSignature+'.log', mod_name=GetInputFile(), output_dir=self.iOutputDir, funcEntry=hex(self.funcEntry-idaapi.get_imagebase()), startTraceCount=self.startTraceCount, traceFileSignature=self.traceFileSignature)
        else:
            cmd = r'"{pin}" -logfile "{pinLogFile}" -t "{pintool}" -logfile "{pintoolLogFile}" -m {mod_name} -o "{output_dir}" -t 3 -s {funcEntry} -sc {startTraceCount} -fs {traceFileSignature}'.format(pin=self.iPinPath, pinLogFile=self.iOutputDir+'\\pin.log', pintool=self.iPinToolPath, pintoolLogFile=self.iOutputDir+'\\'+self.traceFileSignature+'.log', mod_name=GetInputFile(), output_dir=self.iOutputDir, funcEntry=hex(self.funcEntry-idaapi.get_imagebase()), startTraceCount=self.startTraceCount, traceFileSignature=self.traceFileSignature)
        
        if(self.enableEndTrace):
            cmd = (cmd + ' -ec {endTraceCount}').format(endTraceCount=self.endTraceCount)
        
        #cmd epilog
        if(not self.iAttachMode):
            cmd = (cmd + ' -- "{exe_path}"').format(exe_path=self.iTargetPath)
        
        subprocess.Popen(cmd)
        
    def _TraceSingleFunc(self):
        # cmd prolog
        cmd = ''
        if(self.iAttachMode):
            cmd = r'"{pin}" -logfile "{pinLogFile}" -pid {pid} -t "{pintool}" -logfile "{pintoolLogFile}" -m {mod_name} -o "{output_dir}" -t 4 -s {funcEntry} -sc {startTraceCount} -e {funcEnd} -fs {traceFileSignature}'.format(pin=self.iPinPath, pinLogFile=self.iOutputDir+'\\pin.log', pid=self.iTargetPid, pintool=self.iPinToolPath, pintoolLogFile=self.iOutputDir+'\\'+self.traceFileSignature+'.log', mod_name=GetInputFile(), output_dir=self.iOutputDir, funcEntry=hex(self.funcEntry-idaapi.get_imagebase()), startTraceCount=self.startTraceCount, funcEnd=hex(self.funcEnd-idaapi.get_imagebase()), traceFileSignature=self.traceFileSignature)
        else:
            cmd = r'"{pin}" -logfile "{pinLogFile}" -t "{pintool}" -logfile "{pintoolLogFile}" -m {mod_name} -o "{output_dir}" -t 4 -s {funcEntry} -sc {startTraceCount} -e {funcEnd} -fs {traceFileSignature}'.format(pin=self.iPinPath, pinLogFile=self.iOutputDir+'\\pin.log', pintool=self.iPinToolPath, pintoolLogFile=self.iOutputDir+'\\'+self.traceFileSignature+'.log', mod_name=GetInputFile(), output_dir=self.iOutputDir, funcEntry=hex(self.funcEntry-idaapi.get_imagebase()), startTraceCount=self.startTraceCount, funcEnd=hex(self.funcEnd-idaapi.get_imagebase()), traceFileSignature=self.traceFileSignature)
        
        if(self.stepIntoCallee and self.enableEndTrace):
            cmd = (cmd + ' -ec {endTraceCount}').format(endTraceCount=self.endTraceCount)
        elif((not self.stepIntoCallee) and self.enableEndTrace):
            cmd = (cmd + ' -ec {endTraceCount} -l false').format(endTraceCount=self.endTraceCount)
        elif((not self.stepIntoCallee) and (not self.enableEndTrace)):
            cmd += ' -l false'
        else: # default is stepIntoCallee and not enableEndTrace
            pass
        
        # cmd epilog
        if(not self.iAttachMode):
            cmd = (cmd + ' -- "{exe_path}"').format(exe_path=self.iTargetPath)
        
        subprocess.Popen(cmd)
        
    def _TraceMultiFuncGlobal(self):
        self._CreateFuncRangeDB()
        cmd = ''
        if(self.iAttachMode):
            cmd = r'"{pin}" -logfile "{pinLogFile}" -pid {pid} -t "{pintool}" -logfile "{pintoolLogFile}" -m {mod_name} -o "{output_dir}" -t 1 -fs {traceFileSignature}'.format(pin=self.iPinPath, pinLogFile=self.iOutputDir+'\\pin.log', pid=self.iTargetPid, pintool=self.iPinToolPath, pintoolLogFile=self.iOutputDir+'\\'+self.traceFileSignature+'.log', mod_name=GetInputFile(), output_dir=self.iOutputDir, traceFileSignature=self.traceFileSignature)
        else:
            cmd = r'"{pin}" -logfile "{pinLogFile}" -t "{pintool}" -logfile "{pintoolLogFile}" -m {mod_name} -o "{output_dir}" -t 1 -fs {traceFileSignature}'.format(pin=self.iPinPath, pinLogFile=self.iOutputDir+'\\pin.log', pintool=self.iPinToolPath, pintoolLogFile=self.iOutputDir+'\\'+self.traceFileSignature+'.log', mod_name=GetInputFile(), output_dir=self.iOutputDir, traceFileSignature=self.traceFileSignature)
        
        if(not self.stepIntoCallee):
            cmd += ' -l false'
        
        if(not self.iAttachMode):
            cmd = (cmd + ' -- "{exe_path}"').format(exe_path=self.iTargetPath)
        
        subprocess.Popen(cmd)
        
    def callConfig(self):
        f = TraceConfigForm()
        f.Compile()
        
        f.iPinExe.value = self.iPinPath
        f.iTargetExe.value = self.iTargetPath
        f.iOutputDir.value = self.iOutputDir
        
        ok = f.Execute()
        if ok == 1:
            self.iPinPath = f.iPinExe.value
            self.iTargetPath = f.iTargetExe.value
            self.iOutputDir = f.iOutputDir.value
            self.iConfigSet = True
            
        f.Free()
        
    def callTrace(self):
        if(not self.iConfigSet):
            print '[Warning]TraceConfig is not set, please set TraceConfig first'
            return
        
        f = TraceModeForm(self.iAttachMode)
        f.Compile()
        
        f.pin_attach.checked = self.iAttachMode
        f.iTargetPid.value = self.iTargetPid
        f.iTraceMode.value = self.iTraceMode
        
        ok = f.Execute()
        if ok == 1:
            self.iTraceMode = f.iTraceMode.value
            self.iAttachMode = f.pin_attach.checked
            self.iTargetPid = f.iTargetPid.value
        else:
            f.Free()
            return
        
        f.Free()
        
        if(self.iTraceMode == 0): # function count trace mode
            f = ConfirmTraceForm('Start function count trace ?')
            f.Compile()
            ok = f.Execute()
            if ok == 1:
                self.traceFileSignature = self.iModuleName + '_' + self.iModuleExt + '_funcCount'
                self._TraceFuncCount()
            f.Free()
            
        elif(self.iTraceMode == 1): # multi function trace global mode
            c = FuncListChoose2(self.funcListName, self.funcListCols, self.funcList, True)
            f = MultiFuncGlobalTraceForm(c)
            f.Compile()
            ok = f.Execute()
            if ok == 1:
                self.stepIntoCallee = f.step_into_callee.checked
                timeStamp = str(int(time.time())) # get current time, seconds from epoch
                self.traceFileSignature = self.iModuleName + '_' + self.iModuleExt + '_m_' + timeStamp
                
                rangeFile = open(self.iOutputDir+'\\'+self.traceFileSignature+'.range', 'w')
                for func in self.funcList:
                    startEA = int(func[0], 16)
                    endEA = idaapi.get_func(startEA).endEA - 1
                    line = '{start_ea:#x} {end_ea:#x}\n'.format(start_ea = startEA - idaapi.get_imagebase(), end_ea = endEA - idaapi.get_imagebase())
                    rangeFile.write(line)
                rangeFile.close()
                
                self._TraceMultiFuncGlobal()
            f.Free()
            return
            
        elif(self.iTraceMode == 2): # multi function trace 2 mode
            return
            
        elif(self.iTraceMode == 3): # last function trace mode
            self.funcEntry = idaapi.get_func(ScreenEA()).startEA
            
            funcCount = self._GetFuncCountFromDB(self.funcEntry)
            if(funcCount <= 0):
                return
            
            f = LastFuncTraceForm()
            f.Compile()
            
            f.iFuncAddr.value = self.funcEntry
            f.iFuncCount.value = funcCount
            f.iStartTraceCount.value = funcCount
            
            ok = f.Execute()
            if ok == 1:
                self.startTraceCount = f.iStartTraceCount.value
                self.enableEndTrace = f.end_trace.checked
                if(f.end_trace.checked):
                    self.endTraceCount = f.iEndTraceCount.value
                
                timeStamp = str(int(time.time())) # get current time, seconds from epoch
                self.traceFileSignature = self.iModuleName + '_' + self.iModuleExt + '_l_' + hex(self.funcEntry)[2:] + '_' + timeStamp
                
                self._TraceLastFunc()
            f.Free()
            
        elif(self.iTraceMode == 4): # single function trace mode
            self.funcEntry = idaapi.get_func(ScreenEA()).startEA
            self.funcEnd = idaapi.get_func(ScreenEA()).endEA - 1
            funcCount = self._GetFuncCountFromDB(self.funcEntry)
            if(funcCount <= 0):
                return
            
            f = SingleFuncTraceForm()
            f.Compile()
            
            f.iFuncAddr.value = self.funcEntry
            f.iFuncCount.value = funcCount
            f.iStartTraceCount.value = funcCount
            
            ok = f.Execute()
            if ok == 1:
                self.startTraceCount = f.iStartTraceCount.value
                self.stepIntoCallee = f.step_into_callee.checked
                self.enableEndTrace = f.end_trace.checked
                if(f.end_trace.checked):
                    self.endTraceCount = f.iEndTraceCount.value
                
                timeStamp = str(int(time.time())) # get current time, seconds from epoch
                self.traceFileSignature = self.iModuleName + '_' + self.iModuleExt + '_s_' + hex(self.funcEntry)[2:] + '_' + timeStamp
                
                self._TraceSingleFunc()
            f.Free()
    
    def stopTrace(self):
        subprocess.call(self.iWorkDir+'\\stop_trace.exe')
    
    def addFunc(self):
        f = ConfirmTraceForm('The current function has been added to list')
        f.Compile()
        f.Execute()
        f.Free()
        for arr in self.funcList:
            if arr[1] == GetFunctionName(ScreenEA()):
                return
        self.funcList.append([hex(idaapi.get_func(ScreenEA()).startEA), GetFunctionName(ScreenEA())])
    
    def showFuncList(self):
        chooser = FuncListChoose2(self.funcListName, self.funcListCols, self.funcList, False)
        id = chooser.show()
        if id != -1:
            idaapi.jumpto(int(self.funcList[id][0], 16))
    
    def listFuncCount(self):
        chooserList = []
        db_file = self.iOutputDir + '\\' + self.iModuleName + '_' + self.iModuleExt + '_funcCount.db'
        if(not os.path.exists(db_file)):
            print '[Warning]No funcCount.db found, plese click TraceConfig to check Output Dir or run function count tracing to generate a new funcCount.db'
            return -1
        sqliteConn = sqlite3.connect(db_file)
        sqliteCur = sqliteConn.cursor()
        for row in sqliteCur.execute('SELECT * FROM FuncCount ORDER BY count DESC'):
            chooserList.append([hex(row[0]+idaapi.get_imagebase()), str(row[1])])
        sqliteCur.close()
        sqliteConn.close()
        chooser = FuncListChoose2('Function Count', [['Function Address', 12], ['Count', 10]], chooserList, False)
        id = chooser.show()
        if id != -1:
            idaapi.jumpto(int(chooserList[id][0], 16))
    
    def setRunTraceInstance(self, instance):
        self.runTraceInstance = instance
    
    # def _createGlobalTable(self, dbFile):
        # sqliteConn = sqlite3.connect(dbFile)
        # sqliteCur = sqliteConn.cursor()
        
        # for row in sqliteCur.execute("SELECT * FROM sqlite_master WHERE name = 'idx_tbl'"):
            # sqliteCur.close()
            # sqliteConn.close()
            # return
        
        # funcList = []
        
        # for row in sqliteCur.execute("SELECT name FROM sqlite_master WHERE name != 'XRef'"): # assume this db is pure clean, no XRef table, no idx_tbl table
            # funcList.append(row[0])
        
        # sqliteCur.execute('CREATE TABLE idx_tbl (Idx INTEGER, ins_rva INTEGER, PRIMARY KEY (Idx))')
        # sqliteCur.execute('CREATE INDEX idx_tbl_index on idx_tbl (Idx, ins_rva)') # index may speed up query but slow in insertion
        
        # mapList = []
        
        # for funcName in funcList:
            # for row in sqliteCur.execute('SELECT Idx, ins_rva FROM ' + funcName):
                # mapList.append((row[0], row[1]))
        
        # for tuple in mapList:
            # sqliteCur.execute('INSERT INTO idx_tbl VALUES (?, ?)', (tuple[0], tuple[1]))
        
        # sqliteConn.commit()
        
        # sqliteCur.close()
        # sqliteConn.close()
    
    def showComms(self):
        f = ShowCommsForm()
        f.Compile()
        
        a = []
        for s in os.listdir(self.iOutputDir):
            if s.rfind('.db') != -1 and s.find(self.iModuleName + '_' + self.iModuleExt) == 0 and s.rfind('funcCount.db') == -1 and s.rfind('funcRange.db') == -1:
                a.append(s)
        
        if(len(a) == 0):
            f.iTraceDBFile.value = ''
        else:
            a.sort(key=lambda s: os.path.getctime(os.path.join(self.iOutputDir, s)))
            f.iTraceDBFile.value = os.path.join(self.iOutputDir, a[-1])
        
        ok = f.Execute()
        if(ok == 1):
            if(f.iTraceDBFile.value != ''):
                #self._createGlobalTable(f.iTraceDBFile.value)
                self.runTraceInstance.callFromConfig(f.iTraceDBFile.value)
        f.Free()
    
    def empty(self):
        pass
    
    def showCmds(self):
        self.cmdsInterface.Execute()
    
    def showHotKeys(self):
        self.runTraceInstance.printUsage()
    
if __name__ == "__main__":
    
    try:
       ex_addmenu_showCmds_ctx
       idaapi.del_menu_item(ex_addmenu_showCmds_ctx)
    except:
       pass
       
    try:
        ex_addmenu_showHotKeys_ctx
        idaapi.del_menu_item(ex_addmenu_showHotKeys_ctx)
    except:
        pass
    
    runTraceParser = RunTraceParser()
    
    ex_addmenu_showCmds_ctx = idaapi.add_menu_item("Edit/Plugins/", "ShowRunTraceCmds", "j", 0, runTraceParser.showCmds, tuple())
    ex_addmenu_showHotKeys_ctx = idaapi.add_menu_item("Edit/Plugins/", "ShowRunTraceHotKeys", "Shift-j", 0, runTraceParser.showHotKeys, tuple())
    
    import RunTrace
    commDBVar = RunTrace.CommDB()
    RunTrace.CommDB.registerHotKeys("commDBVar")
    
    runTraceParser.setRunTraceInstance(commDBVar)
    runTraceParser.callConfig()