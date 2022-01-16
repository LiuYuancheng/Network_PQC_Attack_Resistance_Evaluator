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
URL_LIST = os.path.join(dirpath , "urllist.txt")    # file to save the url need to process.

SRC_TAG = 'Src'
DIS_TAG = 'Dist'
PRO_TAG = 'Prot'
LAY_TAG = 'Layer'
NTE_TAG = 'notEncript'

LAYER_T_TAG = "Transport Layer"
LAYER_S_TAG = "Session Layer"
LAYER_P_TAG = "Presentation layer"
LAYER_A_TAG = "Application layer"

#-------<GLOBAL PARAMTERS>-----------------------------------------------------
# Set the global reference here.
