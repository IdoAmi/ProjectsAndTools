def decimal_to_binary(x, bits):
    binary = bin(x)[2:]
    return binary.zfill(bits)

def twos_complement(binary):
    inverted = ''.join('1' if b == '0' else '0' for b in binary)
    return bin(int(inverted, 2) + 1)[2:].zfill(len(binary))


x = int(input("Enter a random number greater then 0: "))
while(x <= 0):
    x = int(input("I said greater then 0"))

bits = int(input("Enter a random size for memory: "))
print(twos_complement(decimal_to_binary(x, bits)))




