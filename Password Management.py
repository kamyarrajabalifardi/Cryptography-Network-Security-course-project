import hashlib
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import binascii
import textwrap
import numpy as np
from collections import deque
    
def string2hex(a_string):
    return ''.join([format(ord(i),'x') for i in a_string])

def hex2string(a_string):
    return bytearray.fromhex(a_string).decode()

def hex2table(a_string):
    return np.array(textwrap.wrap(a_string,2)).reshape(4,4).transpose().tolist()

def xor_strings(xs, ys):
    a = hex(int(xs, 16) ^ int(ys, 16))[2::]
    if len(a) == 1:
        return '0' + a
    else:
        return a
    
def S_BOX(a_string):
    S = [['63', '7C', '77', '7B', 'F2', '6B', '6F', 'C5', '30', '01', '67', '2B', 'FE', 'D7', 'AB', '76'],
         ['CA', '82', 'C9', '7D', 'FA', '59', '47', 'F0', 'AD', 'D4', 'A2', 'AF', '9C', 'A4', '72', 'C0'],
         ['B7', 'FD', '93', '26', '36', '3F', 'F7', 'CC', '34', 'A5', 'E5', 'F1', '71', 'D8', '31', '15'],
         ['04', 'C7', '23', 'C3', '18', '96', '05', '9A', '07', '12', '80', 'E2', 'EB', '27', 'B2', '75'],
         ['09', '83', '2C', '1A', '1B', '6E', '5A', 'A0', '52', '3B', 'D6', 'B3', '29', 'E3', '2F', '84'],
         ['53', 'D1', '00', 'ED', '20', 'FC', 'B1', '5B', '6A', 'CB', 'BE', '39', '4A', '4C', '58', 'CF'],
         ['D0', 'EF', 'AA', 'FB', '43', '4D', '33', '85', '45', 'F9', '02', '7F', '50', '3C', '9F', 'A8'],
         ['51', 'A3', '40', '8F', '92', '9D', '38', 'F5', 'BC', 'B6', 'DA', '21', '10', 'FF', 'F3', 'D2'],
         ['CD', '0C', '13', 'EC', '5F', '97', '44', '17', 'C4', 'A7', '7E', '3D', '64', '5D', '19', '73'],
         ['60', '81', '4F', 'DC', '22', '2A', '90', '88', '46', 'EE', 'B8', '14', 'DE', '5E', '0B', 'DB'],
         ['E0', '32', '3A', '0A', '49', '06', '24', '5C', 'C2', 'D3', 'AC', '62', '91', '95', 'E4', '79'],
         ['E7', 'C8', '37', '6D', '8D', 'D5', '4E', 'A9', '6C', '56', 'F4', 'EA', '65', '7A', 'AE', '08'],
         ['BA', '78', '25', '2E', '1C', 'A6', 'B4', 'C6', 'E8', 'DD', '74', '1F', '4B', 'BD', '8B', '8A'],
         ['70', '3E', 'B5', '66', '48', '03', 'F6', '0E', '61', '35', '57', 'B9', '86', 'C1', '1D', '9E'],
         ['E1', 'F8', '98', '11', '69', 'D9', '8E', '94', '9B', '1E', '87', 'E9', 'CE', '55', '28', 'DF'],
         ['8C', 'A1', '89', '0D', 'BF', 'E6', '42', '68', '41', '99', '2D', '0F', 'B0', '54', 'BB', '16']  ]  
    return S[int(a_string[0],16)][int(a_string[1],16)].lower()

def inv_S_BOX(a_string): 
    S = [['52', '09', '6A', 'D5', '30', '36', 'A5', '38', 'BF', '40', 'A3', '9E', '81', 'F3', 'D7', 'FB'],
        ['7C', 'E3', '39', '82', '9B', '2F', 'FF', '87', '34', '8E', '43', '44', 'C4', 'DE', 'E9', 'CB'],
        ['54', '7B', '94', '32', 'A6', 'C2', '23', '3D', 'EE', '4C', '95', '0B', '42', 'FA', 'C3', '4E'],
        ['08', '2E', 'A1', '66', '28', 'D9', '24', 'B2', '76', '5B', 'A2', '49', '6D', '8B', 'D1', '25'],
        ['72', 'F8', 'F6', '64', '86', '68', '98', '16', 'D4', 'A4', '5C', 'CC', '5D', '65', 'B6', '92'],
        ['6C', '70', '48', '50', 'FD', 'ED', 'B9', 'DA', '5E', '15', '46', '57', 'A7', '8D', '9D', '84'],
        ['90', 'D8', 'AB', '00', '8C', 'BC', 'D3', '0A', 'F7', 'E4', '58', '05', 'B8', 'B3', '45', '06'],
        ['D0', '2C', '1E', '8F', 'CA', '3F', '0F', '02', 'C1', 'AF', 'BD', '03', '01', '13', '8A', '6B'],
        ['3A', '91', '11', '41', '4F', '67', 'DC', 'EA', '97', 'F2', 'CF', 'CE', 'F0', 'B4', 'E6', '73'],
        ['96', 'AC', '74', '22', 'E7', 'AD', '35', '85', 'E2', 'F9', '37', 'E8', '1C', '75', 'DF', '6E'],
        ['47', 'F1', '1A', '71', '1D', '29', 'C5', '89', '6F', 'B7', '62', '0E', 'AA', '18', 'BE', '1B'],
        ['FC', '56', '3E', '4B', 'C6', 'D2', '79', '20', '9A', 'DB', 'C0', 'FE', '78', 'CD', '5A', 'F4'],
        ['1F', 'DD', 'A8', '33', '88', '07', 'C7', '31', 'B1', '12', '10', '59', '27', '80', 'EC', '5F'],
        ['60', '51', '7F', 'A9', '19', 'B5', '4A', '0D', '2D', 'E5', '7A', '9F', '93', 'C9', '9C', 'EF'],
        ['A0', 'E0', '3B', '4D', 'AE', '2A', 'F5', 'B0', 'C8', 'EB', 'BB', '3C', '83', '53', '99', '61'],
        ['17', '2B', '04', '7E', 'BA', '77', 'D6', '26', 'E1', '69', '14', '63', '55', '21', '0C', '7D']] 
    return S[int(a_string[0],16)][int(a_string[1],16)].lower()
    
def g(num_round, W):
    B = deque([W[i][4*num_round+3] for i in range(0,4)])
    B.rotate(-1)
    B = list(B)
    B = [S_BOX(B[i]) for i in range(0,len(B))]
    RC = ['01', '02', '04', '08', '10', '20', '40', '80', '1b', '36']
    B[0] = xor_strings(B[0],RC[num_round])
    return B

def key_expansion(key):
    W = [[0 for i in range(0,44)]for j in range(0,4)]
    table_key = hex2table(key) #hex2table(string2hex(key))
    for j in range(0,4):
        for i in range(0,4):
            W[i][j] = table_key[i][j]
        
    num_round = 0 
    while num_round <10:   
        for i in range(4*num_round+4,4*num_round + 8):
            B = g(num_round,W)
            for j in range(0,4):
                if i == 4*num_round +4 :    
                    W[j][i] = xor_strings(W[j][i-4],B[j])
                else:
                    W[j][i] = xor_strings(W[j][i-4],W[j][i-1])
        num_round += 1        
    return W

def add_round_key(num_round,W,table_plain):
    table_key = [[W[i][j]for j in range(4*num_round,4*num_round+4)]for i in range(0,4) ]
    temp = [[0 for i in range(0,4)]for j in range(0,4)]
    for i in range(0,4):
        for j in range(0,4):
            temp[i][j] = xor_strings(table_plain[i][j],table_key[i][j])
    return temp

def shift_rows(table_plain):
   temp = [[0 for i in range(0,4)]for j in range(0,4)] 
   for i in range(0,4):
       temp[i] = deque(table_plain[i])
       temp[i].rotate(-i)
       temp[i] = list(temp[i])    
   return temp

def inv_shift_rows(table_cipher):
   temp = [[0 for i in range(0,4)]for j in range(0,4)] 
   for i in range(0,4):
       temp[i] = deque(table_cipher[i])
       temp[i].rotate(+i)
       temp[i] = list(temp[i])    
   return temp
    
def multiply(b,a):
    if b == 1:
        return a
    tmp = (a<<1) & 0xff
    if b == 2:
        return tmp if a <= 127 else tmp^0x1b
    if b == 3:
        return tmp^a if a <= 127 else (tmp^0x1b)^a

def inv_multiply(b,a) :
    if b == 9:
        return multiply(2,multiply(2,multiply(2,a))) ^ a
    
    if b == 11:
        return multiply(2,multiply(2,multiply(2,a)) ^ a) ^ a
    
    if b == 13:
        return multiply(2,multiply(2,multiply(2,a) ^ a)) ^ a
    
    if b == 14:
        return multiply(2,multiply(2,multiply(2,a) ^ a) ^ a)

def mix(S):
   b = [hex(multiply(2,int(S[0],16)) ^ multiply(3,int(S[1],16)) ^ multiply(1,int(S[2],16)) ^ multiply(1,int(S[3],16)))   
        ,    
        hex(multiply(1,int(S[0],16)) ^ multiply(2,int(S[1],16)) ^ multiply(3,int(S[2],16)) ^ multiply(1,int(S[3],16)))   
        ,    
        hex(multiply(1,int(S[0],16)) ^ multiply(1,int(S[1],16)) ^ multiply(2,int(S[2],16)) ^ multiply(3,int(S[3],16)))   
        ,    
        hex(multiply(3,int(S[0],16)) ^ multiply(1,int(S[1],16)) ^ multiply(1,int(S[2],16)) ^ multiply(2,int(S[3],16)))]
   for i in range(0,4):
       b[i] = b[i][2::]
   return b

def inv_mix(S):
    b = [hex(inv_multiply(14,int(S[0],16)) ^ inv_multiply(11,int(S[1],16)) ^ inv_multiply(13,int(S[2],16)) ^ inv_multiply(9,int(S[3],16)))   
        ,    
        hex(inv_multiply(9,int(S[0],16)) ^ inv_multiply(14,int(S[1],16)) ^ inv_multiply(11,int(S[2],16)) ^ inv_multiply(13,int(S[3],16)))   
        ,    
        hex(inv_multiply(13,int(S[0],16)) ^ inv_multiply(9,int(S[1],16)) ^ inv_multiply(14,int(S[2],16)) ^ inv_multiply(11,int(S[3],16)))   
        ,    
        hex(inv_multiply(11,int(S[0],16)) ^ inv_multiply(13,int(S[1],16)) ^ inv_multiply(9,int(S[2],16)) ^ inv_multiply(14,int(S[3],16)))]
    for i in range(0,4):
           b[i] = b[i][2::]
           if len(b[i]) == 1:
               b[i] = '0'+b[i]
    return b

def mix_column(table_plain):
    temp0 = [[0 for i in range(0,4)]for j in range(0,4)] 
    for i in range(0,4):
        temp = mix([table_plain[0][i],table_plain[1][i],table_plain[2][i],table_plain[3][i]])
        temp0[0][i] = temp[0]
        temp0[1][i] = temp[1]
        temp0[2][i] = temp[2]
        temp0[3][i] = temp[3]
    return temp0

def inv_mix_column(table_cipher):
    temp0 = [[0 for i in range(0,4)]for j in range(0,4)] 
    for i in range(0,4):
        temp = inv_mix([table_cipher[0][i],table_cipher[1][i],table_cipher[2][i],table_cipher[3][i]])
        temp0[0][i] = temp[0]
        temp0[1][i] = temp[1]
        temp0[2][i] = temp[2]
        temp0[3][i] = temp[3]
    return temp0

def block_AES_encrypt(key,plain):
    W = key_expansion(key)
    table_plain = hex2table(plain)
    num_round = 0
    table_plain = add_round_key(num_round,W,table_plain)
    num_round += 1

    while(num_round <= 10):
        for i in range(0,4):
            for j in range(0,4):
                table_plain[i][j] = S_BOX(table_plain[i][j])
        table_plain = shift_rows(table_plain) 
        if num_round <= 9:    
            table_plain = mix_column(table_plain) 
        table_plain = add_round_key(num_round,W,table_plain)
        num_round += 1
    cipher = ''
    for i in range(0,4):
        for j in range(0,4):
            cipher = cipher + table_plain[j][i]
    return cipher

def block_AES_decrypt(key,cipher):
    W = key_expansion(key)
    table_cipher = hex2table(cipher)
    num_round = 10
    table_cipher = add_round_key(num_round,W,table_cipher)
    while(num_round>=1):    
        table_cipher = inv_shift_rows(table_cipher)
        for i in range(0,4):
            for j in range(0,4):
                table_cipher[i][j] = inv_S_BOX(table_cipher[i][j])
        num_round -= 1
        table_cipher = add_round_key(num_round,W,table_cipher)
        if num_round > 0:
            table_cipher = inv_mix_column(table_cipher)
    plain = ''
    for i in range(0,4):
        for j in range(0,4):
            plain = plain + table_cipher[j][i]
    return plain

def AES_encrypt(key,plain):
    temp = string2hex(plain)
    temp = temp + '0'*((int(len(temp)/32)+1)*32 - len(temp))
    cipher = ''
    for i in range(0,int(len(temp)/32)):
        C = block_AES_encrypt(key, temp[32*i:32*i+32])
        cipher = cipher + C
    return cipher

def AES_decrypt(key,cipher):
    plain = ''
    for i in range(0,int(len(cipher)/32)):
        P = block_AES_decrypt(key, cipher[32*i:32*i+32])
        plain = plain + P
        i = len(plain)-1
    while(plain[i-2:i]=='00'):
        i -= 2
    return hex2string(plain[0:i-1] )   


def salt_lcg(a_string):
    a_byte_array = bytearray(a_string, "ascii")
    byte_list = []
    for byte in a_byte_array:
        binary_representation = int(byte)
        byte_list.append(binary_representation)
    rand = sum(byte_list)
    a = 1140671485
    c = 128201163
    m = 2**24
    for i in range(6):
        rand = (a*rand + c) % m
    return str(rand)

def hash_salt(salt,a_string):
    temp = salt + a_string
    return hashlib.sha512(temp.encode()).hexdigest()

def add_user(username,password):
    my_file = open('dataset.txt','r')
    temp = my_file.readlines() 
    my_file.close()
    salt = salt_lcg(password + username)
    temp_hash = hash_salt(salt,username+password)
    for i in temp:
        if temp_hash == i[0:-1]:
            print('A user with the same username and password has already been registered!!\n')
            return
    print('successfully registered!\n')    
    my_file = open('dataset.txt','a')    
    my_file.write(temp_hash+'\n')
    my_file.write('\n')
    my_file.close()


def authenticate_user(username,password):
    salt = salt_lcg(username+password)
    my_file = open('dataset.txt')
    temp = my_file.readlines() 
    my_file.close()
    flag = 0
    for i in range(0,len(temp)):
        if temp[i][0:-1].find(hash_salt(salt,username+password)) != -1:
            flag = 1
            break
    if flag == 1:
        return (i,salt,master_key_generator(salt,username,password))        
    else:    
        return (-1,-1,-1)

def master_key_generator(salt,username,password):
    temp = hash_salt(salt,username+password+username)
    return temp[0:32]
    
def save_URL_PASS(pointer, master_key, salt, address, password_for_address):
    my_file = open('dataset.txt')
    temp = my_file.readlines() 
    my_file.close()            
    temp.insert(pointer , AES_encrypt(master_key,salt + address) + '\n')
    temp.insert(pointer+1 , AES_encrypt(master_key,salt + password_for_address) + '\n')        
    my_file = open('dataset.txt','w')
    my_file.writelines(temp)
    my_file.close()
    print('Address & Password have Saved successfully!\n')
    return

def load_URL_PASS(pointer, master_key, salt, address):
    my_file = open('dataset.txt','r')
    temp = my_file.readlines()
    my_file.close()
    cipher_temp = AES_encrypt(master_key,salt+address)
    i = pointer
    while(temp[i] != '\n'):
        if temp[i][0:-1] == cipher_temp:
            plaintext = AES_decrypt(master_key,temp[i+1][0:-1])
            print('your Password for ',address,' : ','\x1b[1;32;40m' + plaintext[len(salt)::] + '\x1b[0m','\n')
            return
        i += 1
    print('You havent any address like this in our database!\n')
    return

def Change_Login_Password(pointer, new_salt, new_master_key, new_password, salt, master_key, username ,password):
    my_file = open('dataset.txt')
    temp = my_file.readlines()
    my_file.close()
    i = pointer
    temp[i] = hash_salt(new_salt, username + new_password) + '\n'
    i += 1
    while(temp[i] != '\n'):
        temp[i] = AES_encrypt(new_master_key,new_salt + AES_decrypt(master_key, temp[i][0:-1])[len(salt)::]) + '\n'
        i+=1
    my_file = open('dataset.txt','w')
    my_file.writelines(temp)
    my_file.close()
    print('Login Password havs changed successfully!\n')
    return
       
def Change_Web_Password(pointer, master_key, salt, address, new_password):
    my_file = open('dataset.txt','r')
    temp = my_file.readlines()
    my_file.close()
    cipher_temp = AES_encrypt(master_key, salt+address)
    i = pointer
    while(temp[i] != '\n'):
        if temp[i][0:-1] == cipher_temp:
            temp[i+1] = AES_encrypt(master_key, salt + new_password) + '\n'
            my_file = open('dataset.txt','w')
            my_file.writelines(temp)
            my_file.close()
            print('The Password of the Address has changed successfully!\n')
            return
        i += 1
    print('You havent any address like this in our database!\n')        
    return

    
state = '0000' #idle

while(True):
    
    if state == '0000':
        print('\x1b[2;36;40m'+'==========','|| Home ||','==========','\x1b[0m')
        print('0 to logout')
        print('1 to login')
        print('2 to register')
        command = input()
        if command == '0':
            break
        if command == '1':
            state = '0001' #authentication 
        if command == '2':
            state = '0010' #save user_pass
    
    if state == '0001':
        print('\x1b[2;36;40m'+'==========','|| Home ||','==========','\x1b[0m')
        username = input('username:')
        password = input('password:')
        print('\n')
        (access_loc,salt,master_key) = authenticate_user(username,password)
        if access_loc != -1:
            print('\x1b[1;36;40m' + 'Access granted ✅\n' + '\x1b[0m')
            state = '0011' #user Account
            #print(style.WHITE)
        else:
            print('\x1b[1;31;40m' + 'Access denied ❌\n' + '\x1b[0m')
            state = '0000'   
     
            
    
    if state == '0010':
        print('\x1b[2;36;40m'+'==========','|| Home ||','==========','\x1b[0m')        
        username = input('username:')
        password = input('password:')
        print('\n')
        add_user(username,password)
        state = '0000'
    
    if state == '0011':
        print('\x1b[2;33;40m'+'==========','|| User Account ||','==========','\x1b[0m')
        print('0 to Go to Home')
        print('1 to save your passwords')
        print('2 to load your password')
        print('3 to change your passwords')
        command = input()
        if command == '0':
            state = '0000'
        if command == '1':
            state = '0100'
        if command == '2':
            state = '0101'
        if command == '3':
            state = '0110'
            
    if state == '0100':
        while(True):
            print('\x1b[2;33;40m'+'==========','|| User Account ||','==========','\x1b[0m')
            command = input('Do you want to add any address and password(YES/NO)? ')
            if command == 'YES':
                address = input('Enter your address: ')
                password_for_address = input('Enter your password: ')
                print('')
                save_URL_PASS(access_loc + 1, master_key, salt, address, password_for_address)
                #pointer += 1
            if command == 'NO':
                state = '0011'
                break
    
    if state == '0101':
        while(True):
            pointer = access_loc + 1           
            print('\x1b[2;33;40m'+'==========','|| User Account ||','==========','\x1b[0m')
            command = input('Have you forgotten any of your passwords(YES/NO)? ')
            if command == 'YES':
                address = input('Enter your address: ')
                load_URL_PASS(pointer, master_key, salt, address)
            if command == 'NO':
                state = '0011'
                break
    
    if state == '0110':
        print('\x1b[2;35;40m'+'==========','|| Privacy & Policy ||','==========','\x1b[0m')
        print('0 to Go to User Account')
        print('1 to change login password')
        print('2 to change password of a website')
        command = input()
        if command == '0':
            state = '0011'
        if command == '1':
            new_password = input('Enter your new password: ')
            new_salt = salt_lcg(new_password + username)
            new_master_key = master_key_generator(new_salt,username,new_password)
            Change_Login_Password(access_loc, new_salt, new_master_key, new_password, salt, master_key, username ,password)
            salt = new_salt
            master_key = new_master_key
            state = '0110'
        if command == '2':
            address = input('Enter your address: ')
            new_password = input('Enter your new password: ')
            Change_Web_Password(access_loc, master_key, salt, address, new_password)
            state = '0110'
            

my_file = open('dataset.txt','r')
temp = my_file.readlines() 
my_file.close()
print(temp)
