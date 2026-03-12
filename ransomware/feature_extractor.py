import numpy as np
import math

def entropy(data):
    if len(data) == 0:
        return 0

    occur = [0]*256

    for b in data:
        occur[b] += 1

    ent = 0
    for x in occur:
        if x:
            p = x/len(data)
            ent -= p * math.log2(p)

    return ent


def extract_features(file_path):

    try:
        with open(file_path,"rb") as f:
            data = f.read(2000000)

        size = len(data)

        ent = entropy(data)

        unique_bytes = len(set(data))

        printable = sum(1 for b in data if 32 <= b <= 126)

        printable_ratio = printable/size if size else 0

        features = [
            size,
            ent,
            unique_bytes,
            printable_ratio
        ]

        return np.array(features).reshape(1,-1)

    except:
        return None