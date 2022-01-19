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
import DataMgr
import uiPanel as pl
PERIODIC = 500      # update in every 500ms

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class UIFrame(wx.Frame):
    """ Main UI frame window."""
    def __init__(self, parent, id, title):
        """ Init the UI and parameters """
        wx.Frame.__init__(self, parent, id, title, size=(800, 560))
        # No boader frame:
        #wx.Frame.__init__(self, parent, id, title, style=wx.MINIMIZE_BOX | wx.STAY_ON_TOP)
        self.SetBackgroundColour(wx.Colour(200, 210, 200))
        self.SetTransparent(gv.gTranspPct*255//100)
        self.SetIcon(wx.Icon(gv.ICO_PATH))
        # define parameters:

        self._buildToolBars()
        # Build UI sizer
        self.SetSizer(self._buidUISizer())

        gv.iDataMgr = DataMgr.DataMgr()

        # Set the periodic call back
        self.lastPeriodicTime = time.time()
        # YC: temporary disable the timer.
        #self.timer = wx.Timer(self)
        #self.updateLock = False
        #self.Bind(wx.EVT_TIMER, self.periodic)
        #self.timer.Start(PERIODIC)  # every 500 ms

#-----------------------------------------------------------------------------
    def _buildToolBars(self):
        menubar = wx.MenuBar()
        fileMenu = wx.Menu()
        helpMenu = wx.Menu()
        fileItemLF = fileMenu.Append(wx.ID_EXIT, 'Load from File', 'Load From File')
        fileItemLD = fileMenu.Append(wx.ID_EXIT, 'Load from Directory', 'Load From File')
        fileItemLI = fileMenu.Append(wx.ID_EXIT, 'Load from Network Interface', 'Load From File')
        menubar.Append(fileMenu, '&Load Data')
        menubar.Append(helpMenu, '&Help')
        self.SetMenuBar(menubar)
        self.Bind(wx.EVT_MENU, self.OnLoadFile, fileItemLF)

#-----------------------------------------------------------------------------
    def OnLoadFile(self, event):
        # Create open file dialog
        openFileDialog = wx.FileDialog(self, "Open", gv.dirpath, "", 
            "Packet Capture Files (*.pcapng;*.cap;*.pcap)|*.pcapng;*.cap;*.pcap", 
            wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)

        openFileDialog.ShowModal()
        path = str(openFileDialog.GetPath())
        openFileDialog.Destroy()
        self.scValTC.SetValue(path)


#--UIFrame---------------------------------------------------------------------
    def _buidUISizer(self):
        """ Build the main UI Sizer. """
        flagsR = wx.LEFT | wx.EXPAND
        mSizer = wx.BoxSizer(wx.VERTICAL)
        mSizer.AddSpacer(5)
        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        hbox1.Add(wx.StaticText(self, label=" Packet Data Source : "),
                  flag=flagsR, border=2)
        hbox1.AddSpacer(2)
        self.scValTC = wx.TextCtrl(self, size=(500, 22))
        hbox1.Add(self.scValTC, flag=flagsR, border=2)  
        hbox1.AddSpacer(2)
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
        #gv.iImagePanel = pl.PanelImge(self)
        #mSizer.Add(gv.iImagePanel, flag=flagsR, border=2)
        mSizer.AddSpacer(5)
        #mSizer.Add(wx.StaticLine(self, wx.ID_ANY, size=(-1, 560),
        #                         style=wx.LI_VERTICAL), flag=flagsR, border=2)
        
        bm = wx.StaticBitmap(self, -1, wx.Bitmap("img/title2.png", wx.BITMAP_TYPE_ANY))
        mSizer.Add(bm, flag=wx.LEFT, border=2)
        mSizer.AddSpacer(5)
        #gv.iCtrlPanel = pl.PanelCtrl(self)
        #mSizer.Add(gv.iCtrlPanel, flag=flagsR, border=2)
        return mSizer

    def onDataParse(self, evt):
        filePath = str(self.scValTC.GetValue()).strip()
        if filePath !='':
            print('Load data file: %s' %str(filePath))
            gv.iDataMgr.loadFile(filePath)
            print('Finished')
            if self.filePanel:
                self.filePanel.updateGrid()
        self.progressBar.SetValue(19)

#--UIFrame---------------------------------------------------------------------
    def periodic(self, event):
        """ Call back every periodic time."""
        now = time.time()
        if (not self.updateLock) and now - self.lastPeriodicTime >= gv.gUpdateRate:
            print("main frame update at %s" % str(now))
            self.lastPeriodicTime = now

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
