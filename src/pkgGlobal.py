#-----------------------------------------------------------------------------
# Name:        pkgGlobal.py
#
# Purpose:     This module is used as a global config file to set constants, 
#              global parameters which will be used in the other modules.
#              
# Author:      Yuancheng Liu
#
# Created:     2020/11/24
# Copyright:   YC
# License:     YC
#-----------------------------------------------------------------------------
import os

print("Current working directory is : %s" % os.getcwd())
dirpath = os.path.dirname(__file__)
print("Current source code location : %s" % dirpath)
APP_NAME = 'Network_PQC_Attack_Resistance_Evaluator_v0.1'
WINDOW_SIZE = (800, 600)

#------<CONSTANTS>-------------------------------------------------------------
PRO_SCORE_REF = os.path.join(dirpath , "ProtocolRef.json")  

SRC_TAG = 'Src'         # source ip tag
DES_TAG = 'Dest'        # destination ip tag
PRO_TAG = 'Prot'        # protocol type tag
LAY_TAG = 'Layer'       # layer type tag
NTE_TAG = 'notEncript'  # not encrypted data layer tag

LAYER_T_TAG = "Transport layer"
LAYER_S_TAG = "Session layer"
LAYER_P_TAG = "Presentation layer"
LAYER_A_TAG = "Application layer"

#------<IMAGES PATH>-------------------------------------------------------------
IMG_FD = 'img'
ICO_PATH = os.path.join(dirpath, IMG_FD, "qs2.ico")
BGIMG_PATH = os.path.join(dirpath, IMG_FD, "title2.png")

#-------<GLOBAL VARIABLES (start with "g")>------------------------------------
# VARIABLES are the built in data type.
gTranspPct = 100    # Windows transparent percentage.
gUpdateRate = 1     # main frame update rate 1 sec.
# For Windows platform run 'D:\Tools\Wireshark>tshark -D' to list all the network interfaces
gInterfaceDict = {
    'Local Area Connection* 2':   '\\Device\\NPF_{4F0FAC32-6553-401E-BBD4-6C2137063A4D}',
    'Local Area Connection* 10':   '\\Device\\NPF_{2728F59D-A4DB-4C89-A261-88E819ADC5BB}',
    'Ethernet 3': '\\Device\\NPF_{091AF408-257D-45A3-BCC9-586038BB69AA}',
    'VMware Network Adapter VMnet1': '\\Device\\NPF_{9ABE362E-3E4E-4243-8339-C26B54BFE68F}',
    'Wi-Fi': '\\Device\\NPF_{172B21B5-878D-41B5-9C51-FE1DD27C469B}',
    'Local Area Connection* 8': '\\Device\\NPF_{EBED9EB0-F08E-424F-A51A-F612E5C01A75}',
    'Local Area Connection* 9':  '\\Device\\NPF_{3C36F7BA-9CBB-4B91-8D2D-C9A95D4C5049}',
    'VMware Network Adapter VMnet8': '\\Device\\NPF_{A4DD37BA-419B-41C1-A626-409FD34E6008}',
    'Local Area Connection* 1': '\\Device\\NPF_{77832240-0D34-45D6-A193-FCF7D5E68903}',
    'Bluetooth Network Connection': '\\Device\\NPF_{51CF574B-6146-4D03-B4FF-E05EA2882356}',
    'Adapter for loopback traffic capture': '\\Device\\NPF_Loopback',
    'Ethernet': '\\Device\\NPF_{6150AC83-FA10-47B4-9802-41E194A3D6FE}',
    'Local Area Connection': '\\Device\\NPF_{8F6C23C0-9B47-4A47-9698-0DCA7C15E5F1} '
}

#-------<GLOBAL PARAMTERS>-----------------------------------------------------
iMainFrame = None   # MainFrame.
iImagePanel = None  # Image panel.
iCtrlPanel = None   # control panel
iDataMgr = None     # data manager.
