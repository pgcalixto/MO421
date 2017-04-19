""" Python module for decrypting a two-time pad """

import sys


def read_ciphertext(filepath):
    """Open ciphertext file for binary reading and return its content

    Args:
        filepath (str): file path for the ciphertext binary file

    Returns:
        bytes: bytes content on the file
    """
    with open(filepath, 'rb') as cipher_file:
        return cipher_file.read()


def read_dictionary(filepath):
    """Open dictionary file for reading and return its content

    Args:
        filepath (string): file path for the dictionary file

    Returns:
        list: list of strings containing the word list
    """
    with open(filepath, 'r') as dict_file:
        return dict_file.read().splitlines()


if len(sys.argv) != 4:
    sys.exit('usage: python3 two_time_pad_attack.py %s %s %s\n  %s' %
             ('ciphertext1', 'ciphertext2', 'dictionary',
              'dictionary: text file containing the list of words to be' +
              ' checked against the ciphertexts'))

# sets global variables
CIPHERTEXT1 = read_ciphertext(sys.argv[1])
CIPHERTEXT2 = read_ciphertext(sys.argv[2])
DICTIONARY = read_dictionary(sys.argv[3])
DICTIONARY_LOWER = [a.lower() for a in DICTIONARY]

CIPHER_XOR = [a ^ b for a, b in zip(CIPHERTEXT1, CIPHERTEXT2)]
CIPHER_LEN = min(len(CIPHERTEXT1), len(CIPHERTEXT2))


def words_in_dictionary(word_list):
    """Checks if all the words in the word list exist in the dictionary.

    Args:
        word_list (list): List of strings containing the words to be checked
                          against the dictionary.

    Returns:
        boolean: If all the words exist in the dictionary.
    """
    for word in word_list:
        word = word.lower()
        raw_word = word.replace("'", '').replace('.', '')
        if word not in DICTIONARY_LOWER and raw_word not in DICTIONARY_LOWER:
            return False
    return True


def check_in_dictionary(text):
    """Checks if all the text is valid according to the dictionary.

    Args:
        text (str): Text to be checked agains the dictionary.

    Returns:
        boolean: If the text is valid according to the dictionary.
    """
    # check if text is printable
    if not text.isprintable():
        return False

    # if there are all complete words in the text
    if text[-1] == ' ':
        # check if all words exist in the dictionary
        if not words_in_dictionary(text.split()):
            return False

    # if the last word is incomplete
    else:
        # check if all words but the last exists in the dictionary
        text = text.split()
        if not words_in_dictionary(text[:-1]):
            return False

        # checks if there is any word in the dictionary which starts with the
        # last word in the plaintext
        word = text[-1].lower()
        raw_word = word.replace("'", '').replace('.', '')
        return any(a for a in DICTIONARY_LOWER if a.startswith(word)) or \
            any(a for a in DICTIONARY_LOWER if a.startswith(raw_word))

    return True


def strings_xor(ints1, ints2):
    """Performs the binary xor of two list of integers.

    Args:
        ints1 (list): First list of int.
        ints2 (list): Second list of int.

    Returns:
        str: String representation of the two strings binary xor.
    """
    bin_xor = [a ^ b for a, b in zip(ints1, ints2)]
    return ''.join([str(chr(a)) for a in bin_xor])


def crib_drag(plaintext1, plaintext2, index1, index2):
    """Performs crib dragging on the plaintexts until completion.

    Args:
        plaintext1 (str): First plaintext.
        plaintext2 (str): Second plaintext.
        index1 (int): Current position in the first plaintext.
        index2 (int): Current position in the second plaintext.

    Returns:
        str, str: The two plaintexts if completed, None otherwise.
    """

    print('*****************************')

    # checks if the plaintext is finished
    if len(plaintext1) >= CIPHER_LEN:  # or len(plaintext2) >= CIPHER_LEN:
        return plaintext1, plaintext2

    # checks last word in plaintext1 for its completion
    if plaintext1 is not None and plaintext1 != '' and plaintext1[-1] != ' ':
        last_word = plaintext1.split()[-1]
    else:
        last_word = ''

    # select list of possible completion words given last word discovered
    if last_word is None or last_word == '':
        possible_words = DICTIONARY
    else:
        possible_words = [a for a in DICTIONARY
                          if a.startswith(plaintext1.split()[-1])]

    # for each possible word, add a space to it and xor it with the ciphertext
    for word in possible_words:
        new_word = word[len(last_word):] + ' '
        crib_xor = strings_xor(list((plaintext1 + new_word).encode()),
                               CIPHER_XOR[:index1+len(new_word)])

        # if the XORed text is valid according to the dictionary
        if check_in_dictionary(crib_xor):

            # update plaintexts
            plain1 = plaintext1 + new_word
            plain2 = crib_xor

            print("%s" % plain1)
            print("%s" % plain2)

            # recursively crib drags the new plaintexts
            new_plain1, new_plain2 = crib_drag(plain2, plain1,
                                               index2 + len(new_word),
                                               index1 + len(new_word))

            # end of recursion
            if new_plain1 is not None and new_plain2 is not None:
                return new_plain1, new_plain2

    return None, None


def create_plain_file(plaintext, filepath):
    """Creates a file containing the plaintext content

    Args:
        plaintext (str): Plaintext content
        filepath (str): File path to be created/written
    """
    with open(filepath, 'w') as plain_file:
        plain_file.write(plaintext)


def find_key(plaintext1, plaintext2):
    """Finds the key given the 2 plaintexts and ciphertexts

    Args:
        plaintext1 (str): First plaintext
        plaintext2 (str): Second plaintext

    Returns:
        bytes: Key if found, None otherwise.
    """

    # if plain1 XOR cipher1 == plain2 XOR cipher2
    xor1 = strings_xor(list(plaintext1.encode()), list(CIPHERTEXT1))
    xor2 = strings_xor(list(plaintext2.encode()), list(CIPHERTEXT2))
    if xor1 == xor2:
        return xor1.encode()

    # if plain1 XOR cipher2 == plain2 XOR cipher1
    xor1 = strings_xor(list(plaintext1.encode()), list(CIPHERTEXT2))
    xor2 = strings_xor(list(plaintext2.encode()), list(CIPHERTEXT1))
    if xor1 == xor2:
        return xor1.encode()

    return None


def main():
    """Main function of the module, responsible for the decryption logic"""

    # performs crib dragging using initial values
    plaintext1, plaintext2 = crib_drag('', '', 0, 0)

    if plaintext1 is None or plaintext2 is None:
        print('No possible English decryption using the current dictionary')
        return

    # find the key and creates file with results
    plaintext1 = plaintext1[:CIPHER_LEN]
    plaintext2 = plaintext2[:CIPHER_LEN]
    key = find_key(plaintext1, plaintext2)

    with open('plaintext1.txt', 'w') as plain_file:
        plain_file.write(plaintext1)
    with open('plaintext2.txt', 'w') as plain_file:
        plain_file.write(plaintext2)
    with open('key.txt', 'wb') as plain_file:
        plain_file.write(key)


if __name__ == '__main__':
    main()
