#===============================================================================
# IDA tag
# Allow a user to tag the places he/she has already explored. For different item
# use different color.
#
# Usage:
# 
#    Place cursor at the position you want to tag,
#    Hotkey for tag:  'Shift-c'.
#	      tag table:  'Shift-Space'
#		 delete tag:  'Shift-Ctrl-c'
#
# Created by: razygon
#===============================================================================

import idapython
import string

# Global constants
_IDATAG_GUID          = '7f73b19b-507c-41d3-842e-50f6115a0116'  
_IDATAG_HOTKEY        = 'Shift-c'
_DELETETAG_HOTKEY          = 'Shift-Space'
_TAGTABLE_HOTKEY           = 'Shift-Ctrl-c'
#_IDATAG_COLOR_DEFAULT = 0xFFFFFFFF  # idc.DEFCOLOR  


# Globals
_g_CT_IsFirstRun   = True
g_TaggedLines      = None
g_ColorMaster      = None

CIC_ID = CIC_ITEM  #default

if (idapython.IsBackgroundDark()):  
    _IDAtag_COLOR_TAG = 0x5C871F
else:
    _IDAtag_COLOR_TAG = 0xE5FCC5

def CT_LoadPersistData():
  '''
  Load the persistent data.

  Load the persistent data, if it exists, taking care to initialize our
  variables if no data exists.

  '''
  global _g_CT_IsFirstRun,  g_TaggedLines, g_ColorMaster
  
  # Initialize the globals objects
  from color import ColorMaster
  g_ColorMaster = ColorMaster()
  
  g_TaggedLines      = idapython.PersistStore('IDAtag_TaggedLines', _IDATAG_GUID)
 
  # Load persistent data

  g_TaggedLines.Load()

  # Check for no data

  if (g_TaggedLines.data is None):
    g_TaggedLines.data = []
    g_TaggedLines.Save()

  color = idapython.GetTrueBackgroundColorHexRGB()

  
    
def ShowAllTags():
    global g_TaggedLines, _g_CT_IsFirstRun
    
    if (_g_CT_IsFirstRun):
        _g_CT_IsFirstRun = False
        CT_LoadPersistData()
    idc.Message('\n[IDA Tag] All tags:\n')
    if [] == g_TaggedLines.data:
        idc.Message('No tag')
#    print '[ShowAllTags: before sort]'
    g_TaggedLines.data.sort()
#    print '[ShowAllTags: after sort]'
    function_name = g_TaggedLines.data[0][0]
    print function_name + ':'
    
    flag = 1
    for ea in [x[1] for x in g_TaggedLines.data]:
#       print '[ShowAllTags: in for]'
       idx = [x[1] for x in g_TaggedLines.data].index(ea) 
#       print  idx 
       
       if(function_name == g_TaggedLines.data[idx][0]):        
           if 0 != flag%4:
               idc.Message('0x%x (%s)\t' % (ea, g_TaggedLines.data[idx][2]))
               flag += 1
           else:
               flag = 1
               idc.Message('0x%x (%s)\n' % (ea, g_TaggedLines.data[idx][2]))
       else:
           flag = 1
           function_name = g_TaggedLines.data[idx][0]
           print '\n' + function_name + ':'
           idc.Message('0x%x (%s)\t' % (ea, g_TaggedLines.data[idx][2]))
           flag += 1
           
        
def GetComment(ea):
    comment = idc.GetCommentEx(ea,1)
    if '' == comment:
        comment = idc.GetCommentEx(ea,0)
    return comment

def addtag():
    global _g_CT_IsFirstRun, g_TaggedLines, g_ColorMaster
    # Load persistant data if this is the first run
    if (_g_CT_IsFirstRun):
        _g_CT_IsFirstRun = False
        CT_LoadPersistData()

    ea = ScreenEA()
    if ea in [x[1] for x in g_TaggedLines.data]:
        idc.Message('\n[IDA Tag]0x%x is already recorded, can delete then reedit it' % ea)
        return
    g_ColorMaster.add(ea, _IDAtag_COLOR_TAG, _IDAtag_COLOR_TAG)
    default_tag_string = GetComment(ea)
    tag_info = idc.AskStr(default_tag_string, 'Type the Tag Info')

    idc.Message('\n[IDA Tag]0x%x is tagged ' % ea)
    
    # save the tagged addresses, sorted by function
    function_name = GetFunctionName(ea)
    g_TaggedLines.data.append((function_name,ea,tag_info))    
    g_TaggedLines.Save()
    
    idc.Refresh()

# delete 1 tag
def deleteTag():
    
    global g_TaggedLines, _g_CT_IsFirstRun
    
    if (_g_CT_IsFirstRun):
        _g_CT_IsFirstRun = False
        CT_LoadPersistData()
     
    ea = ScreenEA()
    if ea in [x[1] for x in g_TaggedLines.data]:
        idx = [x[1] for x in g_TaggedLines.data].index(ea)  
        g_ColorMaster.remove(ea,_IDAtag_COLOR_TAG)
        delete_tag = g_TaggedLines.data[idx]
        g_TaggedLines.data.remove(delete_tag)       
        idc.Message( '\n[Delete Tag]: 0x%x is deleted' % ea)
        idc.Refresh()
        g_TaggedLines.Save()          
    else:
        idc.Message('\n[Delete Tag] no tag info...')  
        idc.Refresh()
      
  
if __name__ == "__main__":
    #register the Lhotkeys
    print '(IDA_tag)[add tag]    Press "%s"'%_IDATAG_HOTKEY
    print '         [delete tag] Press "%s"' %_DELETETAG_HOTKEY 
    print '         [show tag table] Press "%s"' %_TAGTABLE_HOTKEY
    
    #Add the hotkeys
    idaapi.CompileLine('static __addtag(){ RunPythonStatement("addtag()");}')
    idc.AddHotkey(_IDATAG_HOTKEY, '__addtag')
    idaapi.CompileLine('static __deleteTag(){ RunPythonStatement("deleteTag()");}')
    idc.AddHotkey(_DELETETAG_HOTKEY, '__deleteTag')
    idaapi.CompileLine('static __ShowTag(){ RunPythonStatement("ShowAllTags()");}')
    idc.AddHotkey(_TAGTABLE_HOTKEY, '__ShowTag')
    
    