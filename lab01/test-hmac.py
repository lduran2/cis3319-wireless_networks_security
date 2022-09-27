

from hmac import sha256

# data used for tests
input_string = 'The quick brown fox jumps over the lazy dog'
output_sha256 = 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592'

def test_sha256():
    result_sha256 = sha256(input_string.encode('utf-8'))
    assert output_sha256==result_sha256
    
    print("sha256 tested")

print("Testing... \033[1;32m")

test_sha256()

print("All tests passed!" + "\033[0m")
