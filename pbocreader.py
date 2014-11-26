#!/usr/bin/which python

from smartcard.System import readers
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard import CardConnection
from smartcard.util import *
from tlv import TLV, to_ascii

from time import sleep
from binascii import *

PSE='1PAY.SYS.DDF01'
PPSE='2PAY.SYS.DDF01'

SELECT = [0x00, 0xA4, 0x04, 0x00]
READRECORD = [0x00, 0xB2]
GPO = [0x80, 0xA8, 0x00, 0x00]
GETDATA = [0x80, 0xCA]

DEBUG=False

pboccard = {}

def transmit(apdu):
    resp = card.connection.transmit(apdu)
    return resp

def lvenc(value):
    value = value.replace(' ', '')
    value = hex2bytearray(value) 
    return [len(value)] + value

def hex2bytearray(hex):
    return bs2hl(unhexlify(hex))

def selectcmd(select):
    apdu = SELECT + lvenc(select) + [0x0]
    return apdu

def readrecord(sfi, part):
    apdu = READRECORD + [part, (sfi<<3)|0x4] 
    return apdu

def gpo(pdol):
    pdollv = lvenc(pdol)
    data = [0x83] + pdollv
    apdu = GPO + lvenc(toHexString(data))
    return apdu

def getdata(entry):
    apdu = GETDATA + hex2bytearray(entry) + [0x0]
    return apdu

def debugprint(resp):
    response, sw1, sw2 = resp
    if DEBUG is True:
        print 'response: ', toHexString(response), ' status words: ', "%x %x" % (sw1, sw2)

def selectpse():
    apdu = selectcmd(hexlify(PSE))
    resp = transmit(apdu)
    debugprint(resp)
    response, sw1, sw2 = resp
    if sw1!=0x90 or sw2!=0x0:
        return False
    if response[0] == 0x6F:
        # FCI
        tlv = tlvit(response)
        sfi = tlv.findtag('88')
        if sfi != None:
            pboccard['88'] = sfi
            return True
    return False

def readddf():
    sfi = int(pboccard['88'], 16)
    apdu = readrecord(sfi, 0x1)
    resp = transmit(apdu)
    debugprint(resp)
    response, sw1, sw2 = resp
    if sw1!=0x90 or sw2!=0x0:
        return False
    if response[0] == 0x70:
        # record
        tlv = tlvit(response)
        aid = tlv.findtag('4F')
        if aid != None:
            pboccard['4F'] = aid
        app = tlv.findtag('50')
        if app != None:
            pboccard['50'] = app
    return False

def selectaid():
    if not pboccard.has_key('4F') or pboccard['4F'] is None:
        aid = 'A0  00  00  03  33  01  01  01'
    else:
        aid = pboccard['4F']

    apdu = selectcmd(aid)
    resp = transmit(apdu)
    debugprint(resp)
    response, sw1, sw2 = resp
    if sw1!=0x90 or sw2!=0x0:
        return False
    if response[0] == 0x6F:
        # AID
        tlv = tlvit(response)
        pdol = tlv.findtag('9F38')
        if pdol != None:
            pboccard['9F38'] = pdol
            return True
    return False
            
def startgpo():
    apdu = gpo('600000000000000000000000000000000156000000000001561309250000000000')
    resp = transmit(apdu)
    debugprint(resp)
    response, sw1, sw2 = resp
    if sw1!=0x90 or sw2!=0x0:
        return False
    if response[0] == 0x80:
        # GPO
        tlv = tlvit(response)
        tag80 = tlv.findtag('80')
        aip = tag80[:4]
        pboccard['aip'] = aip
        n = 8
        afls = [tag80[i:i+n] for i in range(4, len(tag80), n)]
        pboccard['afls'] = afls
        return True
    return False

def readafl():
    for afl in pboccard['afls']:
        sfi = int('0x%s'%afl[:2], 16)
        startpart = int('0x%s'%afl[2:4], 16)
        endpart = int('0x%s'%afl[4:6], 16)
        for i in range(startpart, endpart+1):
            apdu = readrecord(sfi>>3, i)
            resp = transmit(apdu)
            debugprint(resp)
            response, sw1, sw2 = resp
            if sw1!=0x90 or sw2!=0x0:
                return False
            if response[0] == 0x70:
                # record
                tlv = tlvit(response)
                cardinfo(tlv)

def readcardinfo():
    tags = ('9F36', '9F79')
    for i in tags:
        apdu = getdata(i)
        resp = transmit(apdu)
        debugprint(resp)
        response, sw1, sw2 = resp
        if sw1!=0x90 or sw2!=0x0:
            return False
        tlv = tlvit(response)
        cardinfo(tlv)
            

def readhist():
    history = []
    for i in range(1, 11):
        apdu = readrecord(0xB, i)
        resp = transmit(apdu)
        debugprint(resp)
        response, sw1, sw2 = resp
        if sw1!=0x90 or sw2!=0x0:
            continue
        history.append(parsetrans(response))
    pboccard['transhist'] = history

def printcardinfo():
    '''    var5F25 = tlv.findtag('5F25')
    var5F24 = tlv.findtag('5F24')
    var50 = tlv.findtag('50')
    var5A = tlv.findtag('5A')
    var9F36 = tlv.findtag('9F36')
    var5F20 = tlv.findtag('5F20')
    var9F61 = tlv.findtag('9F61')
    var9F62 = tlv.findtag('9F62')
    var9F36 = tlv.findtag('9F36')
    var9F79 = tlv.findtag('9F79')'''
    print 'AID: ', pboccard['4F']
    print 'APP: ', to_ascii(a2b_hex(pboccard['50']), True)
    print 'PAN: ', pboccard['5A']
    print 'VALID: ', pboccard['5F25']
    print 'EXPIRE: ', pboccard['5F24']
    print 'ATC: ', pboccard['9F36']
    if pboccard.has_key('5F20') and pboccard['5F20'] is not None:
        cardholder = 'CARDHOLDER: %s'%to_ascii(a2b_hex(pboccard['5F20']), True)
    else:
        cardholder = 'CARDHOLDER: '
    if pboccard.has_key('9F0B') and pboccard['9F0B'] is not None:
        cardholder = cardholder + ' %s'%to_ascii(a2b_hex(pboccard['9F0B']), True)
    else:
        pass
    print cardholder
    
    if pboccard.has_key('9F61') and pboccard['9F61'] is not None:
        print 'ID: ', to_ascii(a2b_hex(pboccard['9F61']), True)
    else:
        print 'ID: '
    print 'IDTYPE: ', pboccard['9F62']
    print 'ECASH BALANCE: ', pboccard['9F79']


def printtranshist():
    for i in pboccard['transhist']:
        print 'DATE: %s, TIME: %s, AMOUNT: %s, MERCHANT: %s, TRANSTYPE: %s, ATC: %s'%(i['transdate'], i['transtime'], i['amount'], i['merchant'], i['transtype'], i['transatc'])

def parsetrans(data):
    trans = dict()
    trans['transdate'] = toHexString(data[:3]).replace(' ', '')
    trans['transtime'] = toHexString(data[3:6]).replace(' ', '')
    trans['amount'] = toHexString(data[6:12]).replace(' ', '')
    trans['merchant'] = to_ascii(a2b_hex(toHexString(data[22:42]).replace(' ', '')), True)
    trans['transtype'] = toHexString(data[42:43]).replace(' ', '')
    trans['transatc'] = toHexString(data[43:45]).replace(' ', '')
    return trans


def tlvit(data):
    resphex = toHexString(data).replace(' ', '')
    tlv = TLV(resphex, False)
    if DEBUG is True:
        print tlv.pretty_print()
    return tlv

def cardinfo(tlv):
    var5F25 = tlv.findtag('5F25')
    var5F24 = tlv.findtag('5F24')
    var50 = tlv.findtag('50')
    var5A = tlv.findtag('5A')
    var9F36 = tlv.findtag('9F36')
    var5F20 = tlv.findtag('5F20')
    var9F0B = tlv.findtag('9F0B')
    var9F61 = tlv.findtag('9F61')
    var9F62 = tlv.findtag('9F62')
    var9F36 = tlv.findtag('9F36')
    var9F79 = tlv.findtag('9F79')

    if not pboccard.has_key('5F25'):
        pboccard['5F25'] = None
    if not pboccard.has_key('5F24'):
        pboccard['5F24'] = None
    if not pboccard.has_key('50'):
        pboccard['50'] = None
    if not pboccard.has_key('5A'):
        pboccard['5A'] = None
    if not pboccard.has_key('9F36'):
        pboccard['9F36'] = None
    if not pboccard.has_key('5F20'):
        pboccard['5F20'] = None
    if not pboccard.has_key('9F0B'):
        pboccard['9F0B'] = None
    if not pboccard.has_key('9F61'):
        pboccard['9F61'] = None
    if not pboccard.has_key('9F62'):
        pboccard['9F62'] = None
    if not pboccard.has_key('9F36'):
        pboccard['9F62'] = None
    if not pboccard.has_key('9F79'):
        pboccard['9F79'] = None


    if pboccard['5F25'] is None and var5F25 is not None:
        pboccard['5F25'] = var5F25
    if pboccard['5F24'] is None and var5F24 is not None:
        pboccard['5F24'] = var5F24
    if pboccard['50'] is None and var50 is not None:
        pboccard['50'] = var50
    if pboccard['5A'] is None and var5A is not None:
        pboccard['5A'] = var5A
    if pboccard['9F36'] is None and var9F36 is not None:
        pboccard['9F36'] = var9F36
    if pboccard['9F0B'] is None and var9F0B is not None:
        pboccard['9F0B'] = var9F0B
    if pboccard['5F20'] is None and var5F20 is not None:
        pboccard['5F20'] = var5F20
    if pboccard['9F61'] is None and var9F61 is not None:
        pboccard['9F61'] = var9F61    
    if pboccard['9F62'] is None and var9F62 is not None:
        pboccard['9F62'] = var9F62
    if pboccard['9F36'] is None and var9F36 is not None:
        pboccard['9F36'] = var9F36
    if pboccard['9F79'] is None and var9F79 is not None:
        pboccard['9F79'] = var9F79

def transhist():
#    apdu = getdata('9F4F')
#    print apdu
    pass
 

def logic():
    selectpse()
    readddf()
    selectaid()
    ret = startgpo()
    if ret == True:
        readafl()
    readcardinfo()
    readhist()
    printcardinfo()
    printtranshist()

'''    apdu = readrecord(0xC, 0x1)
    resp = transmit(apdu)
    gotresp(resp)

    apdu = selectcmd('a0  00  00  03  33  01  01  01')
    resp = transmit(apdu)
    print toHexString(apdu)
    gotresp(resp)

    apdu = gpo('600000000000000000000000000000000156000000000001561309250000000000')
    resp = transmit(apdu)
    gotresp(resp)
'''


cardtype = AnyCardType()
cardrequest = CardRequest( timeout=10, cardType=cardtype )
card = cardrequest.waitforcard()
card.connection.connect()

logic()
#transhist()

