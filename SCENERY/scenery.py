
from parser import stpcommands
from ciphers.cipher import AbstractCipher


class SceneryCipher(AbstractCipher):
    name = "Scenery"

    def getFormatString(self):
        """
        Returns the print format.
        """
        # return ['S', 'P', 'w']
        return ['X', 'S', 'F', 'P', 'w']

    def createSTP(self, stp_filename, parameters):

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% SCENERY w={}"
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            # s = sbox (non-linear), p = pbox+lbox+swap (linear)
            x = ["X{}".format(i) for i in range(rounds + 1)]
            s = ["S{}".format(i) for i in range(rounds + 1)]
            m = ["M{}".format(i) for i in range(rounds + 1)]
            f = ["F{}".format(i) for i in range(rounds + 1)]
            p = ["P{}".format(i) for i in range(rounds + 1)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            # stpcommands.setupVariables(stp_file, s, wordsize)
            # stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, m, wordsize)
            stpcommands.setupVariables(stp_file, f, wordsize)
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupSceneryRound(stp_file, x[i], s[i], f[i], m[i], p[i], x[i+1],
                                      w[i])

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupSceneryRound(self, stp_file, x_in, s, f, m, p, x_out, w):

        command = ""

        # Substitution Layer
        scenery_sbox = [0x6, 0x5, 0xC, 0xA, 0x1, 0xE, 0x7, 0x9, 0xB, 0x0, 0x3, 0xD, 0x8, 0xF, 0x4, 0x2]

        # SBOX
        for i in range(8):
            variables = ["{0}[{1}:{1}]".format(x_in, i + 56),
                         "{0}[{1}:{1}]".format(x_in, i + 48),
                         "{0}[{1}:{1}]".format(x_in, i + 40),
                         "{0}[{1}:{1}]".format(x_in, i + 32),
                         "{0}[{1}:{1}]".format(s, i + 24),
                         "{0}[{1}:{1}]".format(s, i + 16),
                         "{0}[{1}:{1}]".format(s, i + 8),
                         "{0}[{1}:{1}]".format(s, i + 0),
                         "{0}[{1}:{1}]".format(w, i + 24),
                         "{0}[{1}:{1}]".format(w, i + 16),
                         "{0}[{1}:{1}]".format(w, i + 8),
                         "{0}[{1}:{1}]".format(w, i + 0)]
            command += stpcommands.add4bitSbox(scenery_sbox, variables)

        # shift once to calculate t and z
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 0, m, 4)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 1, m, 5)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 2, m, 6)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 3, m, 7)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 4, m, 0)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 5, m, 1)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 6, m, 2)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 7, m, 3)
        
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 8, m, 9)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 9, m, 10)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 10, m, 11)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 11, m, 12)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 12, m, 13)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 13, m, 14)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 14, m, 15)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 15, m, 8)

        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 16, m,17)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 17, m,18)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 18, m,19)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 19, m,20)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 20, m,21)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 21, m,22)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 22, m,23)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 23, m,16)

        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 24, m,29)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 25, m,30)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 26, m,31)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 27, m,24)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 28, m,25)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 29, m,26)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 30, m,27)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 31, m,28)

        # shift again for getting new values
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 0, m, 37)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 1, m, 38)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 2, m, 39)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 3, m, 32)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 4, m, 33)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 5, m, 34)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 6, m, 35)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 7, m, 36)
        
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 8, m, 40)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 9, m, 41)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 10, m, 42)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 11, m, 43)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 12, m, 44)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 13, m, 45)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 14, m, 46)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 15, m, 47)

        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 16, m, 48)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 17, m, 49)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 18, m, 50)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 19, m, 51)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 20, m, 52)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 21, m, 53)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 22, m, 54)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 23, m,55)

        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 24, m,62)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 25, m,63)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 26, m,56)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 27, m,57)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 28, m,58)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 29, m,59)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 30, m,60)
        command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(s, 31, m,61)

        # XOR for shifts
        # L0 = L0 >>> 2 XOR L1 <<< 1 XOR L0 >>> 3
        command += "ASSERT({0}[31:24] = BVXOR({1}[63:56], BVXOR({2}[23:16], {3}[31:24])));\n".format(f, m, m, m)
        # L1 = L1 XOR L1 <<< 1 XOR L0 >>> 3
        command += "ASSERT({0}[23:16] = BVXOR({1}[55:48], BVXOR({2}[23:16], {3}[31:24])));\n".format(f, m, m, m)
        # L2 = L2 XOR L3 <<< 4 XOR L2 <<< 1
        command += "ASSERT({0}[15:8] = BVXOR({1}[47:40], BVXOR({2}[7:0], {3}[15:8])));\n".format(f, m, m, m)
        # L3 = L3 >>> 3 XOR L3 <<< 4 XOR L2 <<< 1
        command += "ASSERT({0}[7:0] = BVXOR({1}[39:32], BVXOR({2}[7:0], {3}[15:8])));\n".format(f, m, m, m)

        # Feistel structure
        command += "ASSERT({0}[3:0] = BVXOR({1}[3:0],{2}[3:0]));\n".format(p, x_in, f)
        command += "ASSERT({0}[7:4] = BVXOR({1}[7:4],{2}[7:4]));\n".format(p, x_in, f)
        command += "ASSERT({0}[11:8] = BVXOR({1}[11:8],{2}[11:8]));\n".format(p, x_in, f)
        command += "ASSERT({0}[15:12] = BVXOR({1}[15:12],{2}[15:12]));\n".format(p, x_in, f)
        command += "ASSERT({0}[19:16] = BVXOR({1}[19:16],{2}[19:16]));\n".format(p, x_in, f)
        command += "ASSERT({0}[23:20] = BVXOR({1}[23:20],{2}[23:20]));\n".format(p, x_in, f)
        command += "ASSERT({0}[27:24] = BVXOR({1}[27:24],{2}[27:24]));\n".format(p, x_in, f)
        command += "ASSERT({0}[31:28] = BVXOR({1}[31:28],{2}[31:28]));\n".format(p, x_in, f)
        # command += "ASSERT({0}[63:32] = {1}[63:32]);\n".format(x_in, p)

        # command += "ASSERT({0}[63:60] = {1}[63:60]);\n".format(x_in, p)
        # command += "ASSERT({0}[59:56] = {1}[59:56]);\n".format(x_in, p)
        # command += "ASSERT({0}[55:52] = {1}[55:52]);\n".format(x_in, p)
        # command += "ASSERT({0}[51:48] = {1}[51:48]);\n".format(x_in, p)
        # command += "ASSERT({0}[47:44] = {1}[47:44]);\n".format(x_in, p)
        # command += "ASSERT({0}[43:40] = {1}[43:40]);\n".format(x_in, p)
        # command += "ASSERT({0}[39:36] = {1}[39:36]);\n".format(x_in, p)
        # command += "ASSERT({0}[35:32] = {1}[35:32]);\n".format(x_in, p)

        command += "ASSERT(0x00000000 = {0}[63:32]);\n".format(f)
        command += "ASSERT(0x00000000 = {0}[63:32]);\n".format(s)
        command += "ASSERT(0x00000000 = {0}[63:32]);\n".format(p)

        command += "ASSERT({0}[63:32] = {1}[31:0]);\n".format(x_in, x_out)
        command += "ASSERT({0}[31:0] = {1}[63:32]);\n".format(p, x_out)



        stp_file.write(command)
        return
