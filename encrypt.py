import sys

def long_key():
    key_string = "01020304"
    return bytes.fromhex(key_string)

def xor32(buf):
    xor_key = long_key()

    for i in range(len(buf)):
        # XOR each byte with the corresponding byte from the xor_key
        buf[i] ^= xor_key[i % len(xor_key)]


def printShellcode(shellcode):
    # Convert shellcode to hex bytes format with a maximum of 16 bytes per line
    hex_bytes = [f'0x{x:02X}' for x in shellcode]
    num_bytes = len(hex_bytes)
    num_rows = (num_bytes + 15) // 16

    # Print the hex bytes format with a maximum of 16 bytes per line
    print(f'[i] Encrypted shellcode in hex bytes format:\n')
    print('unsigned char shellcodeBytes[] = {')
    for i in range(num_rows):
        row_start = i * 16
        row_end = min(row_start + 16, num_bytes)
        row_hex = ', '.join(hex_bytes[row_start:row_end])
        if i == num_rows - 1:
            # Remove the last comma for the last row
            print(f'    {row_hex}')
        else:
            print(f'    {row_hex},')
    print('};\n')


def main():
    if len(sys.argv) != 3:
        print("Usage: {} input_file output_file".format(sys.argv[0]))
        sys.exit(1)

    input_file_name = sys.argv[1]
    output_file_name = sys.argv[2]

    # Read input file into a bytearray
    with open(input_file_name, "rb") as input_file:
        input_data = bytearray(input_file.read())

    # Apply the XOR encryption
    xor32(input_data)
    
    printShellcode(input_data)

    # Write the encrypted data to the output file
    with open(output_file_name, "wb") as output_file:
        output_file.write(input_data)

    print("[i] Saved encrypted file as: {}".format(output_file_name))

if __name__ == "__main__":
    main()
