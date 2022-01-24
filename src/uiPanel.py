#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        uiPanel.py
#
# Purpose:     This module is used to create a grid to show all the connection
#              protocol details and a text field to list one p2p connection
#              packets detail information.
# 
# Author:      Yuancheng Liu
#
# Created:     2022/01/17
# Version:     v_0.1
# Copyright:   YC @ Singtel Cyber Security Research & Development Laboratory
# License:     YC
#-----------------------------------------------------------------------------
import wx
import wx.grid
from datetime import datetime

import pkgGlobal as gv

SCORE_COLOR = (
    wx.Colour(194, 5, 7),
    wx.Colour(255, 13, 13),
    wx.Colour(255, 78, 17),
    wx.Colour(255, 142, 21),
    wx.Colour(250, 183, 51),
    wx.Colour(172, 179, 52),
    wx.Colour(123, 182, 97),
    wx.Colour(105, 179, 76),
    wx.Colour(0, 86, 63),
    wx.Colour(1, 50, 32),)

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class PanelProtocolDetail(wx.Panel):
    """ Panel used to show all the p2p protocol details."""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.SetBackgroundColour(wx.Colour(200, 210, 200))
        self.SetSizer(self._buidUISizer())

#-----------------------------------------------------------------------------
    def _buidUISizer(self):
        """ Build the control panel sizer. """
        flagsR = wx.LEFT | wx.EXPAND
        ctSizer = wx.BoxSizer(wx.HORIZONTAL)
        
        self.grid = wx.grid.Grid(self)
        self.grid.SetColLabelSize(30)
        self.grid.SetRowLabelSize(30)
        self.grid.CreateGrid(11, 4)
        self.grid.SetColSize(0, 100)
        self.grid.SetColLabelValue(0, "Src_IPaddr")
        self.grid.SetColSize(1, 100)
        self.grid.SetColLabelValue(1, "Dest_IPaddr")
        self.grid.SetColSize(2, 80)
        self.grid.SetColLabelValue(2, "Packet_Num")
        self.grid.SetColSize(3, 80)
        self.grid.SetColLabelValue(3, "QS_Score")
        self.grid.Bind(wx.grid.EVT_GRID_LABEL_LEFT_CLICK, self.updateComDetail)
        ctSizer.Add(self.grid, flag=flagsR, border=2)
        
        ctSizer.AddSpacer(3)
        ctSizer.Add(wx.Button(self, label='>>', size=(25, 25)), flag=wx.CENTER, border=2)

        ctSizer.AddSpacer(3)
        self.detailTC = wx.TextCtrl(self, size=(330, 300), style=wx.TE_MULTILINE)
        ctSizer.Add(self.detailTC, flag=flagsR, border=2)
        return ctSizer

#-----------------------------------------------------------------------------
    def updateGrid(self):
        """ Update the protocol information grid. """
        # clear grid data and score cells' bg color.
        self.grid.ClearGrid()
        self.updateTFDetail(None)
        for i in range(self.grid.GetNumberRows()):
            self.grid.SetCellBackgroundColour(i, 3, wx.Colour(255, 255, 255))        
        if gv.iDataMgr.getProtocalDict() is None or gv.iDataMgr.getScoreDict() is None: return 
        
        rowIdx = 0
        for key, value in gv.iDataMgr.getProtocalDict().items():
            if rowIdx > 10: self.grid.AppendRows(numRows=1, updateLabels=True)
            # set protocol info cells
            self.grid.SetCellValue(rowIdx, 0, value.getSourceIPaddr())
            self.grid.SetCellValue(rowIdx, 1, value.getDistIPaddr())
            self.grid.SetCellValue(rowIdx, 2, str(value.getTotolPktNum()))   
            # set the score cells 
            score = gv.iDataMgr.getScoreDict()[key] if key in gv.iDataMgr.getScoreDict().keys() else 0.0
            self.grid.SetCellBackgroundColour(rowIdx, 3, SCORE_COLOR[int(score//1)])
            #self.grid.SetCellTextColour(rowIdx, 3, wx.Colour(0, 0, 0))
            self.grid.SetCellValue(rowIdx, 3, str(score))
            rowIdx += 1

#-----------------------------------------------------------------------------
    def updateComDetail(self, evt):
        """ Update the peers communication connection detail on the text field."""
        rowIdx = int(evt.GetRow())
        srcIP = self.grid.GetCellValue(rowIdx, 0)
        distIP = self.grid.GetCellValue(rowIdx, 1)
        if srcIP != '' and distIP != '':
            keyStr= srcIP +'-'+distIP
            # print(keyStr)
            if keyStr in gv.iDataMgr.getProtocalDict().keys():
                self.updateTFDetail(None) # clear the text field.
                self.updateTFDetail("----- %s -----" % str(datetime.today()))
                dataSet = gv.iDataMgr.getProtocalDict()[keyStr]
                self.updateTFDetail("Src IP address : %s" %str(dataSet.getSourceIPaddr()))
                self.updateTFDetail("Dest IP address : %s" %str(dataSet.getDistIPaddr()))
                self.updateTFDetail("Total Pecket Num : %s" %str(dataSet.getTotolPktNum()))
                self.updateTFDetail("Total TCP Pecket Num : %s" %str(dataSet.getTcpPktNum()))
                self.updateTFDetail("Total UDP Pecket Num : %s" %str(dataSet.getUdpPktNum()))
                self.updateTFDetail("Encryption Layer Section :")
                for key, val in dataSet.getEncriptDict().items():
                    self.updateTFDetail(' > ' + str(key) + ' : ' + str(val))
            self.updateTFDetail("----- ******* -----")
            self.updateTFDetail(" Quantum attack resistance confidence level (0-10):\n [ %s ]" %str(gv.iDataMgr.getScoreDict()[keyStr]))
            self.updateTFDetail("----- Finished -----")
        evt.Skip()

    #-----------------------------------------------------------------------------
    def updateTFDetail(self, data):
        """ Update the data in the detail text field. Input 'None' will clear the 
            detail information in text field.
        """
        if data is None:
            self.detailTC.Clear()
        else:
            self.detailTC.AppendText(" - %s \n" %str(data))

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def main():
    """ Main function used for local test debug panel. """
    print('TestCase start: type in the panel you want to check:')
    print('0 - PanelImge')
    print('1 - PanelCtrl')
    #pyin = str(input()).rstrip('\n')
    #testPanelIdx = int(pyin)
    testPanelIdx = 0    # change this parameter for you to test.
    print("[%s]" %str(testPanelIdx))
    app = wx.App()
    mainFrame = wx.Frame(gv.iMainFrame, -1, 'Debug Panel',
                         pos=(300, 300), size=(640, 480), style=wx.DEFAULT_FRAME_STYLE)
    if testPanelIdx == 0:
        testPanel = PanelProtocolDetail(mainFrame)
    elif testPanelIdx == 1:
        return
    mainFrame.Show()
    app.MainLoop()

if __name__ == "__main__":
    main()



