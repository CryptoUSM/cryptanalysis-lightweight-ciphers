'''
Created on Apr 18, 2022

@author: Khoo Boo Tap (Steven)
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

class LBCIoTCipher(AbstractCipher):
    """
    Represents the differential behaviour of LBCIoT and can be used
    to find differential characteristics for the given parameters.
    """

    name = "lbciot"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X', 'Y', 'w', 'S']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for LBCIoT with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% LBCIoT w={}"
                      "rounds={}\n\n\n".format(wordsize,rounds))
            stp_file.write(header)

            # Setup variables
            # x = left, y = right
            x = ["X{}".format(i) for i in range(rounds + 1)]
            y = ["Y{}".format(i) for i in range(rounds + 1)]
            s_out = ["S{}".format(i) for i in range(rounds + 1)]
            p1_in = ["p1in{}".format(i) for i in range(rounds + 1)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, s_out, wordsize)
            stpcommands.setupVariables(stp_file, p1_in, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupLBCIoTRound(stp_file, x[i], y[i], x[i+1], y[i+1],
                                      s_out[i], p1_in[i], w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x+y, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
                stpcommands.assertVariableValue(stp_file, y[0], y[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupLBCIoTRound(self, stp_file, x_in, y_in, x_out, y_out, s_out, p1_in, w, wordsize):
        """
        Model for differential behaviour of one round LBCIoT
        y[i+1] = P1(x[i] xor S(y[i] <<< 7))
        x[i+1] = P2(y[i])
        
        """
        command = ""

        #Assert(x[i+1] = P2(y[i]))
        #P2
        command += "ASSERT({0}[4:4] = {1}[0:0]);\n".format(x_out, y_in)
        command += "ASSERT({0}[7:7] = {1}[1:1]);\n".format(x_out, y_in)
        command += "ASSERT({0}[15:15] = {1}[2:2]);\n".format(x_out, y_in)
        command += "ASSERT({0}[11:11] = {1}[3:3]);\n".format(x_out, y_in)

        command += "ASSERT({0}[2:2] = {1}[4:4]);\n".format(x_out, y_in)
        command += "ASSERT({0}[10:10] = {1}[5:5]);\n".format(x_out, y_in)
        command += "ASSERT({0}[1:1] = {1}[6:6]);\n".format(x_out, y_in)
        command += "ASSERT({0}[12:12] = {1}[7:7]);\n".format(x_out, y_in)
        
        command += "ASSERT({0}[3:3] = {1}[8:8]);\n".format(x_out, y_in)
        command += "ASSERT({0}[0:0] = {1}[9:9]);\n".format(x_out, y_in)
        command += "ASSERT({0}[13:13] = {1}[10:10]);\n".format(x_out, y_in)
        command += "ASSERT({0}[5:5] = {1}[11:11]);\n".format(x_out, y_in)       
        
        command += "ASSERT({0}[8:8] = {1}[12:12]);\n".format(x_out, y_in)
        command += "ASSERT({0}[14:14] = {1}[13:13]);\n".format(x_out, y_in)
        command += "ASSERT({0}[6:6] = {1}[14:14]);\n".format(x_out, y_in)
        command += "ASSERT({0}[9:9] = {1}[15:15]);\n".format(x_out, y_in)

        #Assert(y[i+1] = P1(x[i] xor S(y[i] <<< 7))
        command += self.F(y_in, s_out, w)

        #Assert XOR
        command += "ASSERT({} = BVXOR({}, {}));\n".format(p1_in, x_in, s_out)

        #P1
        command += "ASSERT({0}[12:12] = {1}[0:0]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[9:9] = {1}[1:1]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[6:6] = {1}[2:2]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[11:11] = {1}[3:3]);\n".format(y_out, p1_in)

        command += "ASSERT({0}[8:8] = {1}[4:4]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[13:13] = {1}[5:5]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[2:2] = {1}[6:6]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[1:1] = {1}[7:7]);\n".format(y_out, p1_in)
        
        command += "ASSERT({0}[4:4] = {1}[8:8]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[15:15] = {1}[9:9]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[14:14] = {1}[10:10]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[3:3] = {1}[11:11]);\n".format(y_out, p1_in)
        
        command += "ASSERT({0}[0:0] = {1}[12:12]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[5:5] = {1}[13:13]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[10:10] = {1}[14:14]);\n".format(y_out, p1_in)
        command += "ASSERT({0}[7:7] = {1}[15:15]);\n".format(y_out, p1_in)

        stp_file.write(command)
        return

    def F(self, y_in, s_out, w):
        """
        Model for the S function used in LBCIoT
        """
        command = ""

        # Substitution Layer
        s0 = [0, 8, 6, 0xD, 5, 0xF, 7, 0xC, 4, 0xE, 2, 3, 9, 1, 0xB, 0xA]
     

        #s0-1
        variables = ["{0}[{1}:{1}]".format(y_in, 12),
                     "{0}[{1}:{1}]".format(y_in, 11),
                     "{0}[{1}:{1}]".format(y_in, 10),
                     "{0}[{1}:{1}]".format(y_in, 9),
                     "{0}[{1}:{1}]".format(s_out, 3),
                     "{0}[{1}:{1}]".format(s_out, 2),
                     "{0}[{1}:{1}]".format(s_out, 1),
                     "{0}[{1}:{1}]".format(s_out, 0),
                     "{0}[{1}:{1}]".format(w, 3),
                     "{0}[{1}:{1}]".format(w, 2),
                     "{0}[{1}:{1}]".format(w, 1),
                     "{0}[{1}:{1}]".format(w, 0)]
        command += stpcommands.add4bitSbox(s0, variables)

        #s0-2
        variables = ["{0}[{1}:{1}]".format(y_in, 0),
                     "{0}[{1}:{1}]".format(y_in, 15),
                     "{0}[{1}:{1}]".format(y_in, 14),
                     "{0}[{1}:{1}]".format(y_in, 13),
                     "{0}[{1}:{1}]".format(s_out, 7),
                     "{0}[{1}:{1}]".format(s_out, 6),
                     "{0}[{1}:{1}]".format(s_out, 5),
                     "{0}[{1}:{1}]".format(s_out, 4),
                     "{0}[{1}:{1}]".format(w, 7),
                     "{0}[{1}:{1}]".format(w, 6),
                     "{0}[{1}:{1}]".format(w, 5),
                     "{0}[{1}:{1}]".format(w, 4)]
        command += stpcommands.add4bitSbox(s0, variables)

        #s0-3
        variables = ["{0}[{1}:{1}]".format(y_in, 4),
                     "{0}[{1}:{1}]".format(y_in, 3),
                     "{0}[{1}:{1}]".format(y_in, 2),
                     "{0}[{1}:{1}]".format(y_in, 1),
                     "{0}[{1}:{1}]".format(s_out,11),
                     "{0}[{1}:{1}]".format(s_out, 10),
                     "{0}[{1}:{1}]".format(s_out, 9),
                     "{0}[{1}:{1}]".format(s_out, 8),
                     "{0}[{1}:{1}]".format(w, 11),
                     "{0}[{1}:{1}]".format(w, 10),
                     "{0}[{1}:{1}]".format(w, 9),
                     "{0}[{1}:{1}]".format(w, 8)]
        command += stpcommands.add4bitSbox(s0, variables)

        #s0-4
        variables = ["{0}[{1}:{1}]".format(y_in, 8),
                     "{0}[{1}:{1}]".format(y_in, 7),
                     "{0}[{1}:{1}]".format(y_in, 6),
                     "{0}[{1}:{1}]".format(y_in, 5),
                     "{0}[{1}:{1}]".format(s_out, 15),
                     "{0}[{1}:{1}]".format(s_out, 14),
                     "{0}[{1}:{1}]".format(s_out, 13),
                     "{0}[{1}:{1}]".format(s_out, 12),
                     "{0}[{1}:{1}]".format(w, 15),
                     "{0}[{1}:{1}]".format(w, 14),
                     "{0}[{1}:{1}]".format(w, 13),
                     "{0}[{1}:{1}]".format(w, 12)]
        command += stpcommands.add4bitSbox(s0, variables)
      
        
        return command 
