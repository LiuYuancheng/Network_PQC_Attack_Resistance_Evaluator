#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        uiRun.py
#
# Purpose:     This module is used as a sample to create the main wx frame.
#
# Author:      Yuancheng Liu
#
# Created:     2019/01/10
# Copyright:   YC @ Singtel Cyber Security Research & Development Laboratory
# License:     YC
#-----------------------------------------------------------------------------
import os
import sys
import time
import wx
import pkgGlobal as gv
import DataMgr as dm
import uiPanel as pl

PERIODIC = 500      # update in every 500ms
ID_LF = 10
ID_LD = 11
ID_LN = 12
ID_HP = 21

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class UIFrame(wx.Frame):
    """ Main UI frame window."""
    def __init__(self, parent, id, title):
        """ Init the UI and parameters """
        wx.Frame.__init__(self, parent, id, title, size=(800, 600))
        # No boader frame:
        #wx.Frame.__init__(self, parent, id, title, style=wx.MINIMIZE_BOX | wx.STAY_ON_TOP)
        self.SetBackgroundColour(wx.Colour(200, 210, 200))
        self.SetTransparent(gv.gTranspPct*255//100)
        self.SetIcon(wx.Icon(gv.ICO_PATH))

        # define parameters:
        self.capFilePath = ''   # Pcap file path we want to load.
        self.newLoad = False    # flag to identify loaded a new cap file.
        self.updateLock = False

        # Build UI sizer
        self._buildToolBars()
        self.SetSizer(self._buidUISizer())

        # define the data manager thread.
        gv.iDataMgr = dm.DataMgrMT(1, 'DataManager Thread')
        gv.iDataMgr.start()

        # Set the periodic call back
        self.lastPeriodicTime = time.time()
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.periodic)
        self.timer.Start(PERIODIC)  # every 500 ms
        self.Bind(wx.EVT_CLOSE, self.onClose)

#-----------------------------------------------------------------------------
    def _buildToolBars(self):
        menubar = wx.MenuBar()
        fileMenu = wx.Menu()
        helpMenu = wx.Menu()
        fileItemLF = fileMenu.Append(ID_LF, 'Load From File', 'Load From File')
        fileItemLD = fileMenu.Append(ID_LD, 'Load From Directory', 'Load From Directory')
        fileItemLI = fileMenu.Append(ID_LN, 'Load From Network Interface', 'Load From Interface')
        helpItem = helpMenu.Append(ID_HP, 'Help Information', 'Help Information')
        menubar.Append(fileMenu, '&Load Data')
        menubar.Append(helpMenu, '&Help')
    
        self.SetMenuBar(menubar)
        self.Bind(wx.EVT_MENU, self.onLoadFile, fileItemLF)
        self.Bind(wx.EVT_MENU, self.onLoadFile, helpItem)

#--UIFrame---------------------------------------------------------------------
    def _buidUISizer(self):
        """ Build the main UI Sizer. """
        flagsR = wx.LEFT | wx.EXPAND
        mSizer = wx.BoxSizer(wx.VERTICAL)
        
        mSizer.AddSpacer(10)
        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        hbox1.Add(wx.StaticText(self, label=" Packet Data Source : "),
                  flag=flagsR, border=2)
        hbox1.AddSpacer(5)
        self.scValTC = wx.TextCtrl(self, size=(500, 22))
        hbox1.Add(self.scValTC, flag=flagsR, border=2)  
        hbox1.AddSpacer(5)
        self.searchBt = wx.Button(self, label='Parse Data', size=(85, 22))
        self.searchBt.Bind(wx.EVT_BUTTON, self.onDataParse)
        hbox1.Add(self.searchBt, flag=flagsR, border=2)
        mSizer.Add(hbox1, flag=flagsR, border=2)

        mSizer.AddSpacer(5)
        self.progressBar = wx.Gauge(self, range=20)
        mSizer.Add(self.progressBar, flag=flagsR, border=2)
        
        mSizer.AddSpacer(5)
        self.filePanel = pl.PanelFile(self)
        mSizer.Add(self.filePanel, flag=flagsR, border=2)
        
        mSizer.AddSpacer(5)        
        bm = wx.StaticBitmap(self, -1, wx.Bitmap(gv.BGIMG_PATH, wx.BITMAP_TYPE_ANY))
        mSizer.Add(bm, flag=wx.LEFT, border=2)
        mSizer.AddSpacer(3)

        return mSizer

#-----------------------------------------------------------------------------
    def onClose(self, evt):
        gv.iDataMgr.stop()
        self.timer.Stop()
        self.Destroy()

#-----------------------------------------------------------------------------
    def onDataParse(self, evt):
        """ Handle the data parse button press action.
        """
        filePath = str(self.scValTC.GetValue()).strip()
        if filePath != '' and os.path.exists(filePath):
            print('Load data file: %s' % str(filePath))
            gv.iDataMgr.loadFile(filePath)
            self.newLoad = True
            self.progressBar.SetValue(4)
        else:
            print('Warning: File %s not exist.' % str(filePath))
            self.progressBar.SetValue(0)

#-----------------------------------------------------------------------------
    def onLoadFile(self, evt):
        itemId = evt.GetId()
        if itemId == ID_LF:
            # Create open file dialog
            openFileDialog = wx.FileDialog(self, "Open", gv.dirpath, "", 
                "Packet Capture Files (*.pcapng;*.cap;*.pcap)|*.pcapng;*.cap;*.pcap", 
                wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)
            openFileDialog.ShowModal()
            path = str(openFileDialog.GetPath())
            openFileDialog.Destroy()
            self.scValTC.SetValue(path)
        elif itemId == ID_HP:
            self.onHelp(None)

#-----------------------------------------------------------------------------
    def onHelp(self, evt):
        """ Pop-up the Help information window. """
        wx.MessageBox(' If there is any bug, please contect: \n\n \
                        Author:      Yuancheng Liu \n \
                        Email:       liu_yuan_cheng@hotmail.com \n \
                        Created:     2022/01/12 \n \
                        Copyright:   N.A \n \
                        GitHub Link: https://github.com/LiuYuancheng/Packet__Parser_PQCr \n', 
                    'Help', wx.OK)

#-----------------------------------------------------------------------------
    def periodic(self, evt):
        """ Call back every periodic time."""
        now = time.time()
        if (not self.updateLock) and now - self.lastPeriodicTime >= gv.gUpdateRate:
            print("main frame update at %s" % str(now))
            self.lastPeriodicTime = now
            if self.newLoad and not gv.iDataMgr.checkUpdating():
                self.filePanel.updateGrid()
                print(">> update the pcap data once")
                self.progressBar.SetValue(19)
                self.newLoad = False

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class MyApp(wx.App):
    def OnInit(self):
        gv.iMainFrame = UIFrame(None, -1, gv.APP_NAME)
        gv.iMainFrame.Show(True)
        return True

#-----------------------------------------------------------------------------
if __name__ == '__main__':
    app = MyApp(0)
    app.MainLoop()
