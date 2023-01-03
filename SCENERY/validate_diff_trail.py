from scenery_cipher import encrypt as scenery
import random

def randHexVal(length):
    randRes = []
    for i in range(length):
        randRes.append(int("0x" + random.choice("0123456789ABCDEF"), 16))
    return randRes


def getXor(t1, t2):
    res = []
    for i in range(len(t1)):
        res.append(t1[i] ^ t2[i])
    return res


def main():
    # ptdiff = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]
    # -----------------------------------------------------
    ptdiff = [0,2,0,2,0,0,0,2,0xC,0,4,0,0,6,0,4]
    targetCtDiff = [0, 2, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]
    rounds = 2
    weight = 2
    # -----------------------------------------------------

    # -----------------------------------------------------
    # ptdiff = [0,2,0,2,0,0,0,2,0xC,0,4,0,0,6,0,4]
    # targetCtDiff =  [0xC,4,4,6,0,6,0,4,0,2,0,2,0,0,0,2]
    # rounds = 3
    # weight = 4
    # -----------------------------------------------------

    # -----------------------------------------------------
    # ptdiff = [0,0,0,0,3,0,2,0,2,0xA,2,6,1,3,0,5]
    # targetCtDiff = [0,0,0,0,3,0,2,0,0,0,1,0,1,0,0,0]
    # rounds = 4
    # weight = 8
    # -----------------------------------------------------

    # -----------------------------------------------------
    # ptdiff = [0,0,0,0,0,2,0,6,0xE,8,4,0xC,0,0xC,4,8]
    # targetCtDiff = [6,9,0xC,0xC,0,0xC,4,8,0,0,0,0,0,2,0,6]
    # rounds = 5
    # weight = 12
    # -----------------------------------------------------

    # -----------------------------------------------------
    # ptdiff = [0,0,0,0,0,2,0,6,0xE,8,4,0xC,0,0xC,4,8]
    # targetCtDiff = [0,0,0,0,0,2,0,6,2,0,0,0,2,0,2,0]
    # rounds = 4
    # weight = 8
    # -----------------------------------------------------

    # -----------------------------------------------------
    # ptdiff = [0,0,0,0,8,0,0xC,0,0xF,0,0xB,0,0xA,8,0xD,8]
    # targetCtDiff = [4,0,6,0,6,0,4,0,0,0,0,0,8,0,0xC,0]
    # rounds = 1
    # weight = 4
    # -----------------------------------------------------

    # -----------------------------------------------------
    # ptdiff = [1,0xC,1,2,1,2,1,0xC,1,0xB,1,5,2,0xA,3,0]
    # targetCtDiff = [0,0,0,0,0,8,0,0xC,1,0xC,1,2,1,2,1,0xC]
    # rounds = 1
    # weight = 8
    # -----------------------------------------------------


    
    # key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # key = [0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF]
    key = randHexVal(20)
    reqTrial = 2**weight
    repTrial = 2**weight
    successCount = 0
    i = 0


    while i < repTrial and i <= 2**64:
        i+=1
        print("trying: {}".format(i))
        pt1 = randHexVal(16)
        pt2 = getXor(pt1, ptdiff)

        ct1 = scenery(pt1, key, rounds)
        ct2 = scenery(pt2, key, rounds)

        ctdiff = getXor(ct1, ct2)
        print("====================================")
        print("key: {}".format(key))
        print("pt1: {}".format(pt1))
        print("pt2: {}".format(pt2))
        print("ct1: {}".format(ct1))
        print("ct2: {}".format(ct2))
        print("plaintext diff: {}".format(ptdiff))
        print("ciphertext diff: {}".format(ctdiff))
        print("target ct diff: {}".format(targetCtDiff))
        print("====================================")

        if ctdiff == targetCtDiff:
            successCount += 1
        
        if i >= repTrial and successCount <= 0:
            repTrial += 1

        if successCount > 0:
            break
        

    print("no of trials: {}".format(i))
    print("required trials: {}".format(reqTrial))
    print("successCount: {}".format(successCount))

if __name__ == "__main__":
    main()
