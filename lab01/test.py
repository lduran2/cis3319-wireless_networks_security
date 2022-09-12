

from crypto import bit2hex, hex2bit, bitize, debitize, permute, DES

# data used for tests
byts = bytes.fromhex("0002000000000001")
bits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
permuted_bits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]


def test_bitize():
    result_bits: list[int] = bitize(byts)
    for bit, result_bit in zip(bits, result_bits):
        assert bit == result_bit
    
    print("bitize tested")

def test_debitize():
    result_byts: list[int] = debitize(bits)
    for byt, result_byt in zip(byts, result_byts):
        assert byt == result_byt
    
    print("debitize tested")

def test_permute():

    result_bits = permute(bits, DES.IP)

    for permuted_bit, result_bit in zip(permuted_bits, result_bits):
        assert permuted_bit == result_bit

    print("permute tested")

def test_key_gen() -> None:
    key = bytes.fromhex('AABB09182736CCDD')
    key = bitize(key)
    # print(key)

    keys = DES.key_generation(key)
    last_key = bit2hex(keys[-1])
    assert last_key == "181c5d75c66d"
    print("key_gen tested")
      
def test_enc_block() -> None:
    plaintext = bytes.fromhex("123456ABCD132536")
    key = bytes.fromhex("AABB09182736CCDD")
    
    des = DES(key)
    result = des.enc_block(bitize(plaintext))
    result = bit2hex(result).upper()
    # print(result)

    assert result == "C0B7A8D05F3A829C"
    print("enc_block tested")

def test_encrypt() -> None:
    des = DES(bytes.fromhex("AABB09182736CCDD"))
    msg = "Hello World     "
    result = des.encrypt(msg)
    # print(result.hex())
    assert result.hex().lower() == "d1a87d37f5b6bfe101ae4d6a4e1204d4"
    print("encrypt tested")

def test_dec_block() -> None:
    ciphertext = bytes.fromhex("C0B7A8D05F3A829C")
    key = bytes.fromhex("AABB09182736CCDD")
    
    des = DES(key)
    result = des.dec_block(bitize(ciphertext))
    result = bit2hex(result)
    # print(result)

    assert result == "123456ABCD132536".lower()
    print("dec_block tested")

def test_decrypt() -> None:
    des = DES(bytes.fromhex("AABB09182736CCDD"))
    cipher = bytes.fromhex("d1a87d37f5b6bfe101ae4d6a4e1204d4")
    result = des.decrypt(cipher)
    # print(result)
    assert result == "Hello World     "
    print("decrypt tested")

print("Testing... \033[1;32m")

# basic functions
test_bitize()
test_debitize()
test_permute()

test_key_gen()
test_enc_block()
test_encrypt()
test_dec_block()
test_decrypt()


print("All tests passed!" + "\033[0m")
