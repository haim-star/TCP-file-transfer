
# return sub byte array from bytearray
def get_sub_byte_arr(byte_arr: bytearray, from_ind: int, size: int):
    bytes_info = bytearray(size)
    for i in range(from_ind, from_ind + size):
        bytes_info[i - from_ind] = byte_arr[i]
    return bytes_info


# read string from bytearray
def get_str_from_bytes(byte_arr: bytearray, from_ind: int, size: int):
    bytes_info = get_sub_byte_arr(byte_arr=byte_arr, from_ind=from_ind, size=size)
    ret_str = bytes(bytes_info).decode()
    if ret_str.find('\0') != -1:
        ret_str = ret_str[:ret_str.find('\0')]
    return ret_str


# read int from bytearray
def get_int_from_bytes(byte_arr: bytearray, from_ind: int, size: int):
    bytes_info = get_sub_byte_arr(byte_arr=byte_arr, from_ind=from_ind, size=size)
    return int.from_bytes(bytes(bytes_info), "little")


# copy string to byte array
def copy_str_to_bytearray(byte_arr: bytearray, str_to_copy: str, from_ind: int):
    str_bytes = str.encode(str_to_copy)
    for i in range(len(str_bytes)):
        byte_arr[from_ind + i] = str_bytes[i]


# copy int to bytearray
def copy_int_to_bytearray(byte_arr: bytearray, int_to_copy: int, from_ind: int, len_bytes: int):
    int_bytes = int_to_copy.to_bytes(len_bytes, 'little')
    for i in range(len_bytes):
        byte_arr[from_ind + i] = int_bytes[i]


# copy one byte array to another (in specific ind)
def copy_byte_arr_to_byte_arr(from_byte_arr: bytearray, to_byte_arr: bytearray, to_ind: int):
    for i in range(len(from_byte_arr)):
        to_byte_arr[to_ind + i] = from_byte_arr[i]
