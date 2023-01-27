
SBOX = [0x6, 0x5, 0xC, 0xA, 0x1, 0xE, 0x7, 0x9, 0xB, 0x0, 0x3, 0xD, 0x8, 0xF, 0x4, 0x2]

def hex_to_list(x, length=4):
    tempState = []
    while x != 0:
        tempState = [x & 1] + tempState
        x >>= 1

    while len(tempState) < length:
        tempState.insert(0, 0)
    return tempState


def list_to_hex(x):
    tempState = 0
    for i in x:
        tempState = (tempState << 1) | i
    return tempState


def generateKey(key, rounds):
    subKeys = []
    subKeys.append(key[:8])

    keyInBin = []
    for k in range(len(key)):
        keyInBin.extend(hex_to_list(key[k]))
    origKeyInBin = keyInBin.copy()

    for r in range(rounds-1):
        # subcells
        # ------------------------------------
        tempKey1 = keyInBin[12:16]
        # # print("tempKey: {}".format(tempKey))
        subCell1 = SBOX[list_to_hex(tempKey1)]
        # print("subcell1: {}".format(subCell1))
        tempKey2 = keyInBin[28:32]
        subCell2 = SBOX[list_to_hex(tempKey2)]

        keyInBin[12:16] = hex_to_list(subCell1)
        keyInBin[28:32] = hex_to_list(subCell2)
        # ------------------------------------
        # print("key after subcol: {}".format(keyInBin))

        # rotate 11 left
        # ------------------------------------
        keyInBin = keyInBin[11:] + keyInBin[:11]
        # ------------------------------------
        # print("key after rotate: {}".format(keyInBin))

        # add round constants
        # ------------------------------------
        roundInBin = hex_to_list(r+1, 5)
        # print("roundInBin: {}".format(roundInBin))
        constantKey = keyInBin[11:16]
        # print("constantKey: {}".format(constantKey))
        addRoundOut = []

        for i in range(len(roundInBin)):
            addRoundOut.append(constantKey[i] ^ roundInBin[i])

        # print("addRoundOut: {}".format(addRoundOut))
        keyInBin[11:16] = addRoundOut
        # ------------------------------------
        # print("key after add constant: {}".format(keyInBin))

        # dynamic permutation
        # ------------------------------------
        v0 = origKeyInBin[14:16]
        v0Dec = list_to_hex(v0)
        # print("v0Dec: {}".format(v0Dec))

        index = []
        for j in range(0, 10):
            index.append((v0Dec * 2 + j) % 10)

        nextKey = []
        for s in range(0, 10):
            keyLoc = index[s]
            nextKey.extend(keyInBin[8*keyLoc: 8*keyLoc+8])
        # ------------------------------------
        tempSubKey = []
        for x in range(0,8):
            hexKey = list_to_hex(nextKey[x*4:x*4+4])
            tempSubKey.append(hexKey)
        subKeys.append(tempSubKey)
        # print("tempSubKey: {}".format(tempSubKey))
        # print("nextSubKey: {}".format(nextKey))
        origKeyInBin = nextKey.copy()
        keyInBin = nextKey.copy()

    return subKeys

def addRoundKey(state, subKeys):
    tempState = []
    for i in range(len(state)):
        tempState.append(state[i] ^ subKeys[i])
    
    return tempState


def subCols(state):
    stateInBin = []
    for i in range(len(state)):
        stateInBin.extend(hex_to_list(state[i]))
    # print("state in bin: {}".format(stateInBin))
    newStateInBin = [0 for x in range(len(stateInBin))]

    for j in range(8):
        sbit = [stateInBin[j], stateInBin[j+8], stateInBin[j+16], stateInBin[j+24]]
        subBit = SBOX[list_to_hex(sbit)]
        subBitInBin = hex_to_list(subBit)
        newStateInBin[j] = subBitInBin[0]
        newStateInBin[j+8] = subBitInBin[1]
        newStateInBin[j+16] = subBitInBin[2]
        newStateInBin[j+24] = subBitInBin[3]
    return newStateInBin

def mixCols(stateInBin):
    # l0 = [0:8], l1 = [8:16], l2 = [16:24], l3 = [24:31]
    shiftL0_3right = stateInBin[5:8] + stateInBin[0:5]
    shiftL1_1left = stateInBin[9:16] + stateInBin[8:9]
    shiftL2_1left = stateInBin[17:24] + stateInBin[16:17]
    shiftL3_4left = stateInBin[28:32] + stateInBin[24:28]

    shiftL0_2right = stateInBin[6:8] + stateInBin[0:6]
    l1_noshift = stateInBin[8:16]
    l2_noshift = stateInBin[16:24]
    shiftL3_3right = stateInBin[29:32] + stateInBin[24:29]

    newL0 = []
    newL1 = []
    newL2 = []
    newL3 = []

    for i in range(8):
        newL0.append(shiftL0_2right[i] ^ shiftL1_1left[i] ^ shiftL0_3right[i])
        newL1.append(l1_noshift[i] ^ shiftL1_1left[i] ^ shiftL0_3right[i])
        newL2.append(l2_noshift[i] ^ shiftL3_4left[i] ^ shiftL2_1left[i])
        newL3.append(shiftL3_3right[i] ^ shiftL3_4left[i] ^ shiftL2_1left[i])

    newStateInBin = newL0 + newL1 + newL2 + newL3
    # print("newStateInBin: {}".format(newStateInBin))
    newState = []

    for j in range(8):
        newState.append(list_to_hex(newStateInBin[j*4:j*4+4]))

    return newState

def encrypt(plaintext, key, rounds):
    subKeys = generateKey(key, rounds)

    # print("plaintext: {}".format(plaintext))
    # print("subKeys: {}".format(subKeys))
    leftState = plaintext[:8]
    rightState = plaintext[8:]

    for r in range(rounds):
        # print("-------------------------------------")
        # print("round: {}".format(r))
        # print("leftState: {}".format(leftState))
        # print("rightState: {}".format(rightState))
        # print("subKeys: {}".format(subKeys[r]))

        # F Function
        # ---------------------------------------------------
        newLeftState = addRoundKey(leftState, subKeys[r])
        # print("after add round key: {}".format(newLeftState))
        newLeftStateInBin = subCols(newLeftState)
        # print("after sub cols: {}".format(newLeftStateInBin))
        newLeftState = mixCols(newLeftStateInBin)
        # print("after mix cols: {}".format(newLeftState))
        # ---------------------------------------------------

        tempRightState = []
        for i in range(len(rightState)):
            tempRightState.append(newLeftState[i] ^ rightState[i])

        rightState = leftState.copy()
        leftState = tempRightState.copy()
        # print("new state: {}{}".format(leftState, rightState))

    # print("{}{}".format(leftState, rightState))
    return leftState + rightState


def main():
    # test vector
    plaintext = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ciphertext = [0x8, 0x2, 0xE, 0xF, 0xE, 0xD, 0xB, 0xA, 0x3, 0x3, 0x3, 0x6, 0xC, 0xD, 0x9,0x2]
    # --------------

    # test vector
    # plaintext = [0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF]
    # key = [0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF]
    # ciphertext = [0xF, 0x7, 0x5, 0x2, 0xC, 0x8, 0x4, 0xE, 0x8, 0x4, 0x1, 0x2, 0x4, 0xC, 0x5, 0x9]
    # --------------

    rounds = 28
    resCiphertext = encrypt(plaintext, key, rounds)
    print("plaintext: {}".format(plaintext))
    print("key: {}".format(key))
    print("given ciphertext: {}".format(ciphertext))
    print("ciphertext: {}".format(resCiphertext))

if __name__ == '__main__':
    main()
