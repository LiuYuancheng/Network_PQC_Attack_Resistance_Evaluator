#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        uiPanel.py
#
# Purpose:     This module is used to create different function panels.
# Author:      Yuancheng Liu
#
# Created:     2020/01/10
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
                wx.Colour(1, 50, 32),
)
#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class PanelFile(wx.Panel):
    """ Function control panel."""
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.SetBackgroundColour(wx.Colour(200, 210, 200))
        self.SetSizer(self._buidUISizer())
        self.proSumDict = {}
        self.scoreDict = {}

#--PanelCtrl-------------------------------------------------------------------
    def _buidUISizer(self):
        """ build the control panel sizer. """
        flagsR = wx.LEFT | wx.EXPAND
        ctSizer = wx.BoxSizer(wx.HORIZONTAL)
        self.grid = wx.grid.Grid(self)
        self.grid.SetColLabelSize(30)
        self.grid.SetRowLabelSize(30)
        self.grid.CreateGrid(11,4)
        self.grid.SetColSize(0, 100)
        self.grid.SetColLabelValue(0, "Src IP address")
        self.grid.SetColSize(1, 100)
        self.grid.SetColLabelValue(1, "Dist IP address")
        self.grid.SetColSize(2, 80)
        self.grid.SetColLabelValue(2, "Packet Num")
        self.grid.SetColSize(3, 80)
        self.grid.SetColLabelValue(3, "QS Score")

        self.grid.Bind(wx.grid.EVT_GRID_LABEL_LEFT_CLICK, self.updateComDetail)
        ctSizer.Add(self.grid, flag=flagsR, border=2)
        #hbox0 = wx.BoxSizer(wx.HORIZONTAL)
        ctSizer.AddSpacer(3)
        ctSizer.Add(wx.Button(self, label='>>', size=(25, 25)), flag=wx.CENTER, border=2)
        # Row idx 0: show the search key and map zoom in level.
        #hbox0.Add(wx.StaticText(self, label="Control panel".ljust(15)),
        #          flag=flagsR, border=2)
        #ctSizer.Add(hbox0, flag=flagsR, border=2)
        ctSizer.AddSpacer(3)
        self.detailTC = wx.TextCtrl(
            self, size=(330, 300), style=wx.TE_MULTILINE)
        ctSizer.Add(self.detailTC, flag=flagsR, border=2)
        return ctSizer

    def updateGrid(self):
        self.grid.ClearGrid()
        for i in range(self.grid.GetNumberRows()):
            self.grid.SetCellBackgroundColour(i, 3, wx.Colour(255,255,255))
        self.proSumDict = gv.iDataMgr.getProtocalDict()
        self.scoreDict = gv.iDataMgr.getScoreDict()
        if self.proSumDict is None: return 
        if self.scoreDict is None: return
        rowIdx = 0
        for key, value in self.proSumDict.items():
            if rowIdx > 10:
                self.grid.AppendRows(numRows=1, updateLabels=True)

            self.grid.SetCellValue(rowIdx, 0, value.getSourceIPaddr())
            self.grid.SetCellValue(rowIdx, 1, value.getDistIPaddr())
            self.grid.SetCellValue(rowIdx, 2, str(value.getTotolPktNum()))   

            score = str(self.scoreDict[key]) if key in self.scoreDict.keys() else '0'
            v = int(float(score)//1)
            self.grid.SetCellBackgroundColour(rowIdx, 3, SCORE_COLOR[v])
            self.grid.SetCellTextColour(rowIdx, 3, wx.Colour(0,0,0))
            self.grid.SetCellValue(rowIdx, 3, score)
            rowIdx += 1

    def updateComDetail(self, evt):

        rowIdx = int(evt.GetRow())
        srcIP = self.grid.GetCellValue(rowIdx, 0)
        distIP = self.grid.GetCellValue(rowIdx, 1)

        if srcIP != '' and distIP != '':
            keyStr= srcIP +'-'+distIP
            print(keyStr)
            if keyStr in self.proSumDict.keys():
                self.updateDetail(None)
                self.updateDetail("----- %s -----" % str(datetime.today()))
                
                dataSet = self.proSumDict[keyStr]
                self.updateDetail("Src IP address : %s" %str(dataSet.getSourceIPaddr()))
                self.updateDetail("Dist IP address : %s" %str(dataSet.getDistIPaddr()))
                self.updateDetail("Total Pecket Num: %s" %str(dataSet.getTotolPktNum()))
                self.updateDetail("Total TCP Pecket Num: %s" %str(dataSet.getTcpPktNum()))
                self.updateDetail("Total UDP Pecket Num: %s" %str(dataSet.getUdpPktNum()))
                self.updateDetail("Encryption Layer Section:")
                for key, val in dataSet.getEncriptDict().items():
                    self.updateDetail(' > ' + str(key) + ' : ' + str(val))
            self.updateDetail("----- ******* ----- \n")
            self.updateDetail(" Quantum attack resistance confidence level (0-10):\n [ %s ]\n" %str(self.scoreDict[keyStr]))

            self.updateDetail("----- Finished ----- \n")

        evt.Skip()

    def updateDetail(self, data):
        """ Update the data in the detail text field. Input 'None' will clear the 
            detail information text field.
        """
        if data is None:
            self.detailTC.Clear()
        else:
            self.detailTC.AppendText(" - %s \n" %str(data))


#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class PanelImge(wx.Panel):
    """ Panel to display image. """

    def __init__(self, parent, panelSize=(640, 480)):
        wx.Panel.__init__(self, parent, size=panelSize)
        self.SetBackgroundColour(wx.Colour(200, 200, 200))
        self.panelSize = panelSize
        self.bmp = wx.Bitmap(gv.BGIMG_PATH, wx.BITMAP_TYPE_ANY)
        self.Bind(wx.EVT_PAINT, self.onPaint)
        self.SetDoubleBuffered(True)

#--PanelImge--------------------------------------------------------------------
    def onPaint(self, evt):
        """ Draw the map on the panel."""
        dc = wx.PaintDC(self)
        w, h = self.panelSize
        dc.DrawBitmap(self._scaleBitmap(self.bmp, w, h), 0, 0)
        dc.SetPen(wx.Pen('RED'))
        dc.DrawText('This is a sample image', w//2, h//2)

#--PanelImge--------------------------------------------------------------------
    def _scaleBitmap(self, bitmap, width, height):
        """ Resize a input bitmap.(bitmap-> image -> resize image -> bitmap)"""
        #image = wx.ImageFromBitmap(bitmap) # used below 2.7
        image = bitmap.ConvertToImage()
        image = image.Scale(width, height, wx.IMAGE_QUALITY_HIGH)
        #result = wx.BitmapFromImage(image) # used below 2.7
        result = wx.Bitmap(image, depth=wx.BITMAP_SCREEN_DEPTH)
        return result

#--PanelImge--------------------------------------------------------------------
    def _scaleBitmap2(self, bitmap, width, height):
        """ Resize a input bitmap.(bitmap-> image -> resize image -> bitmap)"""
        image = wx.ImageFromBitmap(bitmap) # used below 2.7
        image = image.Scale(width, height, wx.IMAGE_QUALITY_HIGH)
        result = wx.BitmapFromImage(image) # used below 2.7
        return result

#--PanelImge--------------------------------------------------------------------
    def updateBitmap(self, bitMap):
        """ Update the panel bitmap image."""
        if not bitMap: return
        self.bmp = bitMap

#--PanelMap--------------------------------------------------------------------
    def updateDisplay(self, updateFlag=None):
        """ Set/Update the display: if called as updateDisplay() the function will 
            update the panel, if called as updateDisplay(updateFlag=?) the function
            will set the self update flag.
        """
        self.Refresh(False)
        self.Update()

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class PanelCtrl(wx.Panel):
    """ Function control panel."""

    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.SetBackgroundColour(wx.Colour(200, 210, 200))
        self.gpsPos = None
        self.SetSizer(self._buidUISizer())

#--PanelCtrl-------------------------------------------------------------------
    def _buidUISizer(self):
        """ build the control panel sizer. """
        flagsR = wx.CENTER
        ctSizer = wx.BoxSizer(wx.VERTICAL)
        hbox0 = wx.BoxSizer(wx.HORIZONTAL)
        ctSizer.AddSpacer(5)
        # Row idx 0: show the search key and map zoom in level.
        hbox0.Add(wx.StaticText(self, label="Control panel".ljust(15)),
                  flag=flagsR, border=2)
        ctSizer.Add(hbox0, flag=flagsR, border=2)
        return ctSizer

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def main():
    """ Main function used for local test debug panel. """

    print('Test Case start: type in the panel you want to check:')
    print('0 - PanelImge')
    print('1 - PanelCtrl')
    #pyin = str(input()).rstrip('\n')
    #testPanelIdx = int(pyin)
    testPanelIdx = 1    # change this parameter for you to test.
    print("[%s]" %str(testPanelIdx))
    app = wx.App()
    mainFrame = wx.Frame(gv.iMainFrame, -1, 'Debug Panel',
                         pos=(300, 300), size=(640, 480), style=wx.DEFAULT_FRAME_STYLE)
    if testPanelIdx == 0:
        testPanel = PanelImge(mainFrame)
    elif testPanelIdx == 1:
        testPanel = PanelCtrl(mainFrame)
    mainFrame.Show()
    app.MainLoop()

if __name__ == "__main__":
    main()



