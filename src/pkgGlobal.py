#-----------------------------------------------------------------------------
# Name:        pkgGlobal.py
#
# Purpose:     This module is used as a local config file to set constants, 
#              global parameters which will be used in the other modules.
#              
# Author:      Yuancheng Liu
#
# Created:     2020/11/24
# Copyright:   YC @ Singtel Cyber Security Research & Development Laboratory
# License:     YC
#-----------------------------------------------------------------------------
import os

print("Current working directory is : %s" % os.getcwd())
dirpath = os.path.dirname(__file__)
print("Current source code location : %s" % dirpath)
APP_NAME = 'Packet__Parser_PQC_v0.1'

#------<CONSTANTS>-------------------------------------------------------------
PRO_SCORE_REF = os.path.join(dirpath , "ProtocalRef.json")  

SRC_TAG = 'Src'
DIS_TAG = 'Dist'
PRO_TAG = 'Prot'
LAY_TAG = 'Layer'
NTE_TAG = 'notEncript'

LAYER_T_TAG = "Transport Layer"
LAYER_S_TAG = "Session Layer"
LAYER_P_TAG = "Presentation layer"
LAYER_A_TAG = "Application layer"

#------<IMAGES PATH>-------------------------------------------------------------
IMG_FD = 'img'
ICO_PATH = os.path.join(dirpath, IMG_FD, "geoIcon.ico")
BGIMG_PATH = os.path.join(dirpath, IMG_FD, "SampleImg.png")


#-------<GLOBAL VARIABLES (start with "g")>------------------------------------
# VARIABLES are the built in data type.
gTranspPct = 100     # Windows transparent percentage.
gUpdateRate = 1     # main frame update rate 1 sec.


#-------<GLOBAL PARAMTERS>-----------------------------------------------------
iMainFrame = None   # MainFrame.
iImagePanel = None  # Image panel.
iCtrlPanel = None   # control panel

iDataMgr = None
