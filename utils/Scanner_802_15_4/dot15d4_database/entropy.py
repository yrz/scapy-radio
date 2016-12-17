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
