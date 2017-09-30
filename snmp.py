#coding=utf8
import time, random
import struct, socket

class snmp():
    #此类暂时只支持SNMP请求
    INTEGER_TYPE = 0x02
    SQUENCE_TYPE = 0x30
    OCTET_TYPE = 0x04
    NULL_TYPE = 0X05
    OBJID_TYPE = 0x06
    GET_TYPE = 0xa0
    def __init__(self, community):
        self.version = '\x02\x01\x01'
        self.community = struct.pack('2B', self.OCTET_TYPE, len(community)) + community
        self.objid = []
        #ID 默认定义为4个字节长度的随机数
        self.requestid = random.randint(0, 256**4)
    def coding_obj(self, obj):
        objlist = obj.split('.')
        objtemplist = []
        objfir1byte = int(objlist[0])*40 + int(objlist[1])
        objtemplist.append(struct.pack('B', objfir1byte))
        for i in objlist[2:]:
            if int(i)>127:
                a, b = divmod(int(i), 128)
                objtemplist.append(struct.pack('2B', a+128, b))
            else:
                objtemplist.append(struct.pack('B', int(i)))
        return ''.join(objtemplist)
    def coding_of_length(self, len):
        #SNMP中域长度的编码方式。此函数直接返回长度字段的编码结果
        if len<=127:
            return struct.pack('B', len)
        if 127<len<256:
            return struct.pack('2B', 0x81, len)
        if 256<=len<256**2:
            return struct.pack('!BH', 0x82, len)
    def add_obj_buff(self, objid):
        #此函数用来往SNMP报文中添加 OBJ 内容
        self.objid.append(objid)
    def create_obj_buff(self):
        #返回对象组成的 buff，由于是请求，对象的value都0x0500
        reslist = []
        for i in self.objid:
            ibuff = self.coding_obj(i)
            lenobj = len(ibuff)
            reslist.append(struct.pack('4B', self.SQUENCE_TYPE, (lenobj+4), self.OBJID_TYPE, lenobj) + ibuff + '\x05\x00')
        return ''.join(reslist)
    def built_packet(self):
        #此函数用来建立SNMP的报文
        buffobj = self.create_obj_buff()
        buffobj = struct.pack('B', self.SQUENCE_TYPE) + self.coding_of_length(len(buffobj)) + buffobj
        reqid_buff = struct.pack('!2BI', self.INTEGER_TYPE, 4, self.requestid)
        error_status = '\x02\x01\x00'
        error_index = '\x02\x01\x00'
        req_buff = reqid_buff + error_status + error_index + buffobj
        req_buff = struct.pack('B', self.GET_TYPE) + self.coding_of_length(len(req_buff)) + req_buff
        result_buff = self.version + self.community + req_buff
        result_buff = struct.pack('B', self.SQUENCE_TYPE) + self.coding_of_length(len(result_buff)) + result_buff
        return result_buff
def get_r_buff():
    a = snmp('public')
    for i in range(1, 80):
        a.objid.append('1.3.6.1.2.1.2.2.1.' + str(random.randint(1, 30)) + '.' + str(random.randint(1, 30)))
    buff = a.built_packet()
    return buff
def udp_con(dest):
    buff = get_r_buff()
    id=0
    while 1:
        sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sc.connect(dest)
        buff = get_r_buff()
        sc.send(buff)
        time.sleep(0.1)
        print id
        sc.close()
        id+=1

if __name__=='__main__':
    destip = '6.6.6.6'
    SNMPPORT = 161
    destaddr = (destip, SNMPPORT)
    udp_con(destaddr)
