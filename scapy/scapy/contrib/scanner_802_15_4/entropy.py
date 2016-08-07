import math

def calcul_data_entropy(data):
    ''' Return the entropy of <data> '''
    entropy = 0L
    l = len(data)
    if l > 0:
        for x in range(256):
            p_x = float(data.count(chr(x))) / l
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
    return entropy



'''
if __name__ == '__main__':
    
    data1 = "\x91\x4c\x86\xf8\xbd\xeb\x53\x32\x01\x44\x8c\x5c\xae\xf3\x8d\x04\x01\xc5\x7b\x9f\x89\x31\x7a\x31\xc5"
    data2 = "Bonjour tout le monde"*10

    a = "Bonjour tout le mondeBonjour tout le mondeBonjour tout le mondeBonjour tout le mondeBonjour tout le mondeBonjour tout le mondeBonjour tout le mondeBonjour tout le mondeBonjour tout le mondeBonjour tout le m"
    data = "HELLO TOUT LE MO?NDE COMMENT CA VA BIEN"

    print str(calcul_data_entropy(a))
    print str(calcul_data_entropy(data2))
'''
