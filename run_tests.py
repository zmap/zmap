import os

packet_file_path = "./src/probe_modules/packet.c"
tcp_synscan_file_path = "./src/probe_modules/module_tcp_synscan.c"

NUMBER_OF_TESTS = 1

def compile() -> None:
    os.system("cmake . && make -j4")

def set_options_bitmap(bitmap_value:int) -> None:
    #convert bitmap_value into hex
    hex_value = format(bitmap_value, '02x')
    new_line = f"uint8_t options_bitmap = 0x{hex_value};"
    # use sed to replace line in the file
    sed_command = f"sed -i 's/^[[:space:]]*uint8_t options_bitmap = 0x[0-9a-fA-F]*;/{new_line}/' {packet_file_path}"
    print(sed_command)
    os.system(sed_command)

def set_len_fields(bitmap_value: int) -> None:
    bitmap_to_header_len = {
        0: 20,
        1: 24,
        2: 24,
        3: 28,
        4: 32,
        5: 36,
        6: 36,
        7: 40,
        8: 24,
        9: 28,
        10: 28,
        11: 32,
        12: 32,
        13: 36,
        14: 36,
        15: 40
    }
    header_len = bitmap_to_header_len[bitmap_value]
    packet_len = header_len + 34

    header_line = f"define ZMAP_TCP_SYNSCAN_TCP_HEADER_LEN {header_len}"
    packet_line = f"define ZMAP_TCP_SYNSCAN_PACKET_LEN {packet_len}"

    sed_command_header = f"sed -i 's/define ZMAP_TCP_SYNSCAN_TCP_HEADER_LEN [0-9]*/{header_line}/' {tcp_synscan_file_path}"
    sed_command_packet = f"sed -i 's/define ZMAP_TCP_SYNSCAN_PACKET_LEN [0-9]*/{packet_line}/' {tcp_synscan_file_path}"
    os.system(sed_command_header)
    os.system(sed_command_packet)

def process_output()-> None:
    print("bitmap_id,test_num,hits")
    for bitmap_id in range(16):
        for test_num in range(NUMBER_OF_TESTS):
            output_file = get_output_file(bitmap_id, test_num)
            with open(output_file, 'r') as file:
                lines = file.readlines()
                print(f"{bitmap_id},{test_num},{len(lines)}")

def get_output_file(bitmap_value:int, test_num:int) -> str:
    return 'bitmap-' + str(bitmap_value) + '-test-' + str(test_num) + '.csv'


if __name__ == "__main__":
    for bitmap_value in range(16):
        set_options_bitmap(bitmap_value)
        set_len_fields(bitmap_value)
        compile()
        for test_num in range(1):
            print(f"Running test {test_num} with bitmap {bitmap_value}")
            output_file = get_output_file(bitmap_value, test_num)
            # os.system(f"sudo ./src/zmap -o '{output_file}' -p 80 1.1.1.0/2 -c 5 -B 250M --sender-threads=2 -v 2 --seed=4321 -n 3000000")
            os.system(f"sudo ./src/zmap -o '{output_file}' -p 80 1.1.1.0/2 -c 5 -B 250M --sender-threads=2 -v 2 --seed=4321 -n 3000000")
            # os.system(f"sudo ./src/zmap -o '{output_file}' -p 80 1.1.1.1 -c 3 -B 250M --sender-threads=1 -v 2 --seed=4321 -n 30000000")

    process_output()
